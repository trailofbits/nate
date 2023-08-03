use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use anyhow::anyhow;
use byteorder::{ByteOrder, ReadBytesExt};
use crate::{DwarfSections, Error};
use crate::types::{Address, AddressSetIndex, iter_bail_early, RangeListOffsetsIndex, repackage_eof, TaggedRef};
use crate::leb::ULeb128;
use dw5_consts::*;

/// Index for the .debug_addr section.
///
/// This section is used by references from the .debug_rnglists section.
#[derive(Debug)]
pub struct AddressIndex<'a, Order: ByteOrder> {
	index: BTreeMap<usize, AddressSet<'a, Order>>,
}
impl<'a, Order> AddressIndex<'a, Order>
	where Order: ByteOrder {

	pub fn new(sections: &DwarfSections<'a>) -> Result<Self, Error> {
		let addr = sections.addr
			.expect("tried to build an AddressIndex for a binary with no \
				.debug_addr section");

		let addr_sets = {
			let mut cursor = Cursor::new(addr);
			let mut addr_sets = Vec::new();

			while let Some(range_list) =
				TaggedRef::try_next_from_cursor::<Order>(&mut cursor)? {

				addr_sets.push(range_list);
			}

			addr_sets
		};

		let index = addr_sets
			.into_iter()
			.map(|(offset_to_header, range_list_ref)| {
				parse_addr_set(offset_to_header, range_list_ref)
			})
			.collect::<Result<BTreeMap<_, _>, _>>()?;

		Ok(Self {
			index,
		})
	}

	/// Get the address in the the debug addresses section contained in the
	/// entry with the given index in the set with a given
	/// `DW_AT_addr_base` value.
	pub fn get(&self, base: usize, index: AddressSetIndex) -> Option<Address> {
		self.index.range(..=base)
			.last()
			.and_then(|(actual_base, set)| {
				let delta = base - actual_base;
				if delta % set.entry_len() != 0 {
					/* This offset is bogus. Offsets must point to the beginning
					 * of an entry, and this one points to the middle of one. */
					return None
				}

				let index = index
					+ (delta / set.entry_len()) as AddressSetIndex;
				set.get(index)
			})
	}
}

/// Parse an address set from a .debug_addr section.
fn parse_addr_set<Order>(
	offset_to_header: usize,
	addr_set_ref: TaggedRef
) -> Result<(usize, AddressSet<Order>), Error>
	where Order: ByteOrder {

	let mut cursor = Cursor::new(addr_set_ref.as_ref());

	let version = cursor.read_u16::<Order>().map_err(repackage_eof)?;
	if version != 5 {
		return Err(Error::InvalidRangeListsSection {
			source: anyhow!(
				"unknown version {} for addr set {}",
				version,
				addr_set_ref),
		})
	}

	let address_size = cursor.read_u8().map_err(repackage_eof)?;
	let segment_selector_size = cursor.read_u8().map_err(repackage_eof)?;

	let offset_to_first_entry = cursor.position() as usize;

	/* Make sure there is no incomplete data we won't know how to read. */
	let data_len = addr_set_ref.as_ref().len() - offset_to_first_entry;
	let entry_len = segment_selector_size + address_size;
	if data_len % usize::from(entry_len) != 0 {
		return Err(Error::InvalidRangeListsSection {
			source: anyhow!(
				"address set {} does not cleanly fit all of its entries ({} % {} != 0)",
				addr_set_ref,
				data_len,
				entry_len),
		})
	}

	let name = offset_to_header + offset_to_first_entry;
	let address_set = AddressSet {
		address_size,
		segment_selector_size,
		entries: addr_set_ref.slice(offset_to_first_entry..).unwrap(),
		_bind: Default::default(),
	};
	Ok((name, address_set))
}

/// A set of addresses in the .debug_addr section.
#[derive(Debug)]
struct AddressSet<'a, Order: ByteOrder> {
	address_size: u8,
	segment_selector_size: u8,
	entries: TaggedRef<'a>,
	_bind: std::marker::PhantomData<Order>
}
impl<'a, Order> AddressSet<'a, Order>
	where Order: ByteOrder {

	pub fn entry_len(&self) -> usize {
		usize::from(self.address_size) + usize::from(self.segment_selector_size)
	}

	pub fn get(&self, index: AddressSetIndex) -> Option<Address> {
		let address_size = usize::from(self.address_size);
		let segment_selector_size = usize::from(self.segment_selector_size);

		let entry_size = segment_selector_size + address_size;
		let offset = index as usize * entry_size + segment_selector_size;

		let slice = self.entries.as_ref().get(offset..offset + address_size)?;
		let mut cursor = Cursor::new(slice);

		Some(Address::from(cursor.read_uint::<Order>(address_size).unwrap()))
	}
}

/// Index for the .debug_ranges section.
///
/// This section is used by DW_AT_ranges in CUs that are of version 4.
#[derive(Debug)]
pub struct RangesIndex<'a, Order: ByteOrder> {
	/// The size of an address value in this section has to be determined by the
	/// environment. There's no way to determine it from just the DWARF 4 data.
	address_size: u8,
	/// Range list names are the same as the offset from the start of the
	/// section to that list, so, like with strings, we don't have to waste any
	/// time indexing them, and we can index directly into the slice.
	ranges: &'a [u8],
	_bind: std::marker::PhantomData<Order>
}
impl<'a, Order> RangesIndex<'a, Order>
	where Order: ByteOrder {

	pub fn new(sections: &DwarfSections<'a>) -> Result<Self, Error> {
		let address_size = sections.address_size;
		let ranges = sections.ranges
			.expect("tried to build a RangeIndex for a binary with no \
				.debug_ranges section");

		/* Make sure there's no incomplete entries we won't know how to deal
		 * with later down the line. */
		if ranges.len() % (usize::from(address_size) * 2) != 0 {
			return Err(Error::InvalidRangesSection {
				source: anyhow!(
					"size of section ({}) is not divisible by twice the address \
					size in the target architecture ({})",
					ranges.len(),
					address_size
				)
			})
		}

		Ok(Self {
			address_size,
			ranges,
			_bind: Default::default(),
		})
	}

	/// Returns an iterator over all the ranges in the list with the given name.
	/// The base address corresponds to the value of `DW_AT_low_pc`.
	pub fn get(&self, name: usize, low_pc: Address) -> Option<Ranges<'a, Order>> {
		let address_size = usize::from(self.address_size);
		let pair_size = address_size * 2;

		/* Snip out names we know could never name valid lists. */
		let unaligned = name % pair_size != 0;
		let out_of_range_lo = name > 0 && name < pair_size;
		let out_of_range_hi = name > self.ranges.len();

		if unaligned || out_of_range_lo || out_of_range_hi {
			return None
		}

		/* Make sure we are pointing to the start of a list. */
		if name > 0 {
			let mut cursor = Cursor::new(&self.ranges[name - pair_size..]);
			let a = cursor.read_uint::<Order>(address_size).unwrap();
			let b = cursor.read_uint::<Order>(address_size).unwrap();

			if a != 0 || b != 0 {
				/* This is the middle of a list. We don't support that. */
				return None
			}
		}

		/* All good to go. */
		Some(Ranges {
			last_base: low_pc,
			address_size: self.address_size,
			cursor: Cursor::new(&self.ranges[name..]),
			done: false,
			_bind: Default::default(),
		})
	}
}

/// A range of addresses.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Range {
	pub low: Address,
	pub high: Address,
}

/// Iterator over all ranges in a [`RangesIndex`] range list.
#[derive(Debug)]
pub struct Ranges<'a, Order: ByteOrder> {
	/// Last base address value we've seen.
	last_base: Address,
	/// The address size of the target machine.
	address_size: u8,
	/// The cursor we're using to scan through this range list.
	cursor: Cursor<&'a [u8]>,
	/// Whether we're done reading from the cursor.
	done: bool,
	_bind: std::marker::PhantomData<Order>
}
impl<'a, Order> Iterator for Ranges<'a, Order>
	where Order: ByteOrder {

	type Item = Result<Range, Error>;
	fn next(&mut self) -> Option<Self::Item> {
		if self.done { return None }
		let address_size = usize::from(self.address_size);
		let base_sentinel = u64::MAX >> (u64::BITS - u32::from(self.address_size));

		loop {
			let a = self.cursor.read_uint::<Order>(address_size)
				.map_err(repackage_eof);
			let b = self.cursor.read_uint::<Order>(address_size)
				.map_err(repackage_eof);

			let a = iter_bail_early!(self.done, a);
			let b = iter_bail_early!(self.done, b);

			/* Check to see if we've reached the end-of-list entry. */
			if a == 0 && b == 0 {
				self.done = true;
				return None
			}

			/* Check to see if B is a base address value. */
			if a == base_sentinel {
				self.last_base = Address::from(b);
				continue
			}

			break Some(Ok(Range {
				low: Address::from(a) + self.last_base,
				high: Address::from(b) + self.last_base,
			}))
		}
	}
}

/// Index for the .debug_rnglists section.
///
/// This section is used by DW_AT_ranges in CUs that are of version 5.
#[derive(Debug)]
pub struct RangeListIndex<'a, Order: ByteOrder> {
	index: BTreeMap<usize, RangeListSet<'a, Order>>
}
impl<'a, Order> RangeListIndex<'a, Order>
	where Order: ByteOrder {

	pub fn new(sections: &DwarfSections<'a>) -> Result<Self, Error> {
		let rnglists = sections.rnglists
			.expect("tried to build a RangeListIndex for a binary with no \
				.debug_rnglists section");

		let range_lists = {
			let mut cursor = Cursor::new(rnglists);
			let mut range_lists = Vec::new();

			while let Some(range_list) =
				TaggedRef::try_next_from_cursor_with_size::<Order>(&mut cursor)? {

				range_lists.push(range_list);
			}

			range_lists
		};

		let index = range_lists
			.into_iter()
			.map(|(offset_to_header, length_of_range_list_set, range_list_ref)| {
				parse_range_list_set(
					offset_to_header,
					length_of_range_list_set,
					range_list_ref
				)
			})
			.collect::<Result<BTreeMap<_, _>, _>>()?;

		Ok(Self {
			index,
		})
	}

	/// Get the range list at the given `DW_AT_rnglists_base` and index.
	pub fn get(&self,
		base: usize,
		index: RangeListOffsetsIndex
	) -> Option<RangeList<'a, Order>> {
		/* The index doesn't cover the whole object, so base has to match with
		 * the name of the set we're going to query exactly. */
		self.index.get(&base)
			.and_then(|set| set.get(index))
	}
	
	/// Gets the range list starting at the given offset. The offset value is
	/// from the beginning of the section.
	pub fn address(&self, address: usize) -> Option<RangeList<'a, Order>> {
		self.index.range(..=address)
			.last()
			.and_then(|(base, range_list)| {
				/* Get the offset relative to the start of the offset array. */
				let offset = address - *base;
				
				range_list.address(offset)
			})
	}
}

/// Parse a range list set from the .debug_rnglists section.
fn parse_range_list_set<Order>(
	offset_to_header: usize,
	length_of_range_list_set: usize,
	range_list_ref: TaggedRef
) -> Result<(usize, RangeListSet<Order>), Error>
	where Order: ByteOrder {

	let mut cursor = Cursor::new(range_list_ref.as_ref());

	let version = cursor.read_u16::<Order>().map_err(repackage_eof)?;
	if version != 5 {
		return Err(Error::InvalidRangeListsSection {
			source: anyhow!(
				"unknown version {} for range list {}",
				version,
				range_list_ref),
		})
	}

	let address_size = cursor.read_u8().map_err(repackage_eof)?;
	let segment_selector_size = cursor.read_u8().map_err(repackage_eof)?;
	let offset_entry_count = cursor.read_u32::<Order>().map_err(repackage_eof)?;

	let offset_to_first_entry = cursor.position() as usize;

	/* If there are any entries in the offsets array, we should validate that
	 * there is enough space in the data to hold them all ahead of time. */
	let data_len = range_list_ref.as_ref().len() - offset_to_first_entry;
	let offsets_len = offset_entry_count as usize * range_list_ref.size_len();
	if data_len < offsets_len {
		return Err(Error::InvalidRangeListsSection {
			source: anyhow!(
				"range list {} is too small to hold its offsets array ({} < {})",
				range_list_ref,
				data_len,
				offsets_len),
		})
	}

	let name = offset_to_header + offset_to_first_entry;
	let range_list = RangeListSet {
		address_size,
		segment_selector_size,
		offset_entry_count,
		data: range_list_ref.slice(
			/* There's no count for the number of range lists in a set, so we
			 * have to explicitly make sure it won't read past the end of the
			 * set by putting an upper bound in the reference. */
			offset_to_first_entry..length_of_range_list_set
		).unwrap(),
		_bind: Default::default(),
	};
	Ok((name, range_list))
}

#[derive(Debug)]
pub struct RangeListSet<'a, Order: ByteOrder> {
	/// How many bytes in an address value.
	address_size: u8,
	/// How many bytes in a segment selector value.
	segment_selector_size: u8,
	/// How many entries in the offset.
	offset_entry_count: u32,
	/// The combined offset and range lists data.
	data: TaggedRef<'a>,
	_bind: std::marker::PhantomData<Order>
}
impl<'a, Order> RangeListSet<'a, Order>
	where Order: ByteOrder {

	/// Gets the range list pointed to by the given index.
	pub fn get(&self, index: RangeListOffsetsIndex) -> Option<RangeList<'a, Order>> {
		if index >= self.offset_entry_count {
			return None
		}

		let element_len = self.data.size_len();
		let element_off = element_len * index as usize;

		let mut cursor = Cursor::new(self.data.slice(element_off..)?.inner());
		let offset = cursor.read_uint::<Order>(element_len).unwrap() as usize;

		self.address(offset)
	}

	/// Gets the range list starting at the given offset. The offset value is
	/// from the beginning of the offset array.
	pub fn address(&self, offset: usize) -> Option<RangeList<'a, Order>> {
		/* Validating the offset passed to this function would require us to
		 * parse all of the lists in this set ahead of time. While there's
		 * nothing stopping us from doing it, it hasn't been implemented.
		 *
		 * Because of this, we settle for a best effort validation, which skips
		 * checking whether we're really at the start of a list or not. While
		 * this should not affect correctness directly, it makes it harder to detect
		 * correctness bugs in our implementation of the parser. */
		if offset < self.offset_entry_count as usize * self.data.size_len() {
			/* We'd land inside the offsets array. */
			return None
		}
		
		let list = self.data.slice(offset..)?;
		if list.as_ref().len() == 0 {
			/* There's nothing to read. */
			return None
		}

		Some(RangeList {
			address_size: self.address_size,
			segment_selector_size: self.segment_selector_size,
			data: list,
			_bind: Default::default(),
		})
	}
}

/// A handle to a range list in the .debug_rnglists section. These can be
/// obtained from the [`RangeListIndex`].
#[derive(Debug)]
pub struct RangeList<'a, Order: ByteOrder> {
	/// How many bytes in an address value.
	address_size: u8,
	/// How many bytes in a segment selector value.
	segment_selector_size: u8,
	/// The list data.
	data: TaggedRef<'a>,
	_bind: std::marker::PhantomData<Order>
}
impl<'a, Order> RangeList<'a, Order>
	where Order: ByteOrder {

	/// Get an iterator over the ranges in this list. This function takes a
	/// reference to the address index and the value of `DW_AT_addr_base`, as
	/// well as (optionally) the value of `DW_AT_low_pc`.
	///
	/// # Optional value for `DW_AT_low_pc`
	/// Because `DW_AT_low_pc` is used for the initial CU base address value,
	/// and, because in a range list, not all entry types are affected by the
	/// base address, a range list may be valid even if there is no such value
	/// if it only consists of entries that are not affected by it.
	///
	/// Having the value be optional here lets us account for that case, but
	/// reaching an entry that requires this value when it's not present will
	/// result in an error and early stop of the iteration.
	pub fn ranges<'b>(
		&self,
		addr_base: usize,
		addr: &'b AddressIndex<'a, Order>,
		low_pc: Option<Address>,
	) -> RangeListRanges<'b, 'a, Order> {

		/* No need to validate anything here, we're just packaging the arguments
		 * we got into the iterator structure. */
		RangeListRanges {
			addr_base,
			addr,
			last_base: low_pc,
			address_size: self.address_size,
			segment_selector_size: self.segment_selector_size,
			data: Cursor::new(self.data.inner()),
			done: false,
			_bind: Default::default(),
		}
	}
}

/// Iterator over the ranges in a [`RangeList`].
#[derive(Debug)]
pub struct RangeListRanges<'a, 'b, Order: ByteOrder> {
	/// Value of `DW_AT_addr_base` we use to index into the address index.
	addr_base: usize,
	/// A reference to the address index.
	///
	/// Certain entry types in the range list contain indices into the address
	/// section, so we have to keep a reference to the address index in case we
	/// happen across one of those entry types and need to resolve the addresses
	/// it's referencing.
	addr: &'a AddressIndex<'b, Order>,
	/// The last base address value we've seen.
	last_base: Option<Address>,
	/// How many bytes in an address value.
	address_size: u8,
	/// How many bytes in a segment selector value.
	segment_selector_size: u8,
	/// The data in the range list.
	data: Cursor<&'b [u8]>,
	/// Whether we're done processing this list.
	done: bool,
	_bind: std::marker::PhantomData<Order>
}
impl<'a, 'b, Order> Iterator for RangeListRanges<'a, 'b, Order>
	where Order: ByteOrder {

	type Item = Result<Range, Error>;
	fn next(&mut self) -> Option<Self::Item> {
		if self.done { return None }

		/* Get the byte identifying the type of the next entry in the list. */
		let entry_kind = self.data.read_u8().map_err(repackage_eof);
		let entry_kind = iter_bail_early!(self.done, entry_kind);

		/* Reads a ULeb128 value into another type. */
		macro_rules! next_uleb128 {
			() => {{
				let value = ULeb128::next_from_cursor(&mut self.data)
					.map_err(|_| Error::InvalidRangeListsSection {
						source: anyhow!("cannot read inline ULeb128 value")
					});
				let value = iter_bail_early!(self.done, value);

				let value = value.try_into()
					.map_err(|_| Error::InvalidRangeListsSection {
						source: anyhow!("cannot fit inline ULeb128 into target \
						 	value")
					});
				iter_bail_early!(self.done, value)
			}}
		}

		/* Reads an address inline. */
		macro_rules! next_inline_address {
			() => {{
				let segment = if self.segment_selector_size > 0 {
					self.data.read_uint::<Order>(usize::from(self.segment_selector_size))
						.map_err(repackage_eof)
				} else { Ok(0) };
				let address = self.data.read_uint::<Order>(usize::from(self.address_size))
					.map_err(repackage_eof);

				let _segment = iter_bail_early!(self.done, segment);
				let address = iter_bail_early!(self.done, address);

				Address::from(address)
			}}
		}

		/* Reads an indexed address. */
		macro_rules! next_indexed_address {
			() => {{
				let index = next_uleb128!();
				iter_bail_early!(self.done, self.addr.get(self.addr_base, index)
					.ok_or_else(|| Error::InvalidRangeListsSection {
						source: anyhow!("address base 0x{:016x} index {} does \
							not name a valid entry in the address section",
							self.addr_base,
							index)
					}))
			}}
		}

		/* Handle the entry based on the kind value. */
		Some(Ok(loop {
			match entry_kind {
				DW_RLE_end_of_list => {
					/* We're done with this list. */
					self.done = true;
					return None
				},
				DW_RLE_base_address => {
					/* Change the base address to the value of the inline
					 * address operand. */
					let base = next_inline_address!();
					self.last_base = Some(base)
				},
				DW_RLE_base_addressx => {
					/* Change the base address to the value of the inline
					 * address operand. */
					let base = next_indexed_address!();
					self.last_base = Some(base)
				},
				DW_RLE_offset_pair => {
					/* Start and end values are ULeb128 offsets. */
					let low: Address = next_uleb128!();
					let high: Address = next_uleb128!();

					let last_base = iter_bail_early!(self.done, self.last_base
						.ok_or_else(|| Error::InvalidRangeListsSection {
							source: anyhow!("tried to resolve a \
								DW_RLE_offset_pair entry when no DW_AT_low_pc \
								value was given and there is no previous base \
								address entry")
						}));

					break Range {
						low: low + last_base,
						high: high + last_base
					}
				}
				DW_RLE_startx_endx => {
					/* Start and end values are indexed addresses. */
					let low = next_indexed_address!();
					let high = next_indexed_address!();

					/* These aren't affected by the base address. */
					break Range { low, high, }
				},
				DW_RLE_startx_length => {
					/* Start value is an indexed address and length is a ULeb128
					 * value. */
					let low = next_indexed_address!();
					let len: Address = next_uleb128!();

					/* These aren't affected by the base address. */
					break Range {
						low,
						high: low + len
					}
				},
				DW_RLE_start_end | DW_RLE_start_length =>
					/* The wording in the spec for these two makes my brain
					 * melt. So just pray we don't encounter them in the wild
					 * until I have the time to come in and fix this ;-; */
					unimplemented!(),
				_ => {
					self.done = true;
					return Some(Err(Error::InvalidRangeListsSection {
						source: anyhow!("invalid range list value type 0x{:02x}",
						entry_kind)
					}))
				}
			}
		}))
	}
}
