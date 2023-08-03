use std::ffi::CStr;
use std::io::Cursor;
use anyhow::anyhow;
use byteorder::{ByteOrder, ReadBytesExt};
use crate::abbreviation::{Abbreviation, AbbreviationAttribute, AbbreviationCode, AbbreviationIndex};
use crate::Error;
use crate::str::{StringOffsetsIndex, StringsIndex};
use crate::types::{Address, AddressSetIndex, AttributeName, FormName, iter_bail_early, RangeListOffsetsIndex, repackage_eof, StringOffsetsSetIndex, TaggedRef};
use crate::leb::ULeb128;
use dw5_consts::*;
use crate::address::{AddressIndex, RangeList, RangeListIndex};

#[derive(Debug, Clone)]
pub struct CompilationUnit<'a, Order: ByteOrder> {
	/// Tagged reference to the first DIE in this compilation unit.
	die_data: TaggedRef<'a>,
	/// Name of the abbreviation table used by the DIEs in this compilation unit.
	abbreviation_table: usize,
	/// Set of DIE parsing state pertaining to this compilation unit.
	state: CompilationUnitState,
	/// Value of the `address_size` field in the DW_UT_compile header.
	address_size: u8,
	/// Value of the version field in the DW_UT_compile header.
	version: u16,
	/// We have to know what the byte order is.
	_bind: std::marker::PhantomData<Order>,
}
impl<'a, Order> CompilationUnit<'a, Order>
	where Order: ByteOrder {

	pub fn new(
		abbreviation: &AbbreviationIndex<'a>,
		strings: &StringsIndex<'a>,
		str_offsets: &StringOffsetsIndex<'a, Order>,
		addr: Option<&AddressIndex<'a, Order>>,
		rnglists: Option<&RangeListIndex<'a, Order>>,
		compilation_unit: TaggedRef<'a>,
	) -> Result<Self, Error> {
		let mut cursor = Cursor::new(compilation_unit.as_ref());

		/* Read the version field and read the header accordingly.
		 *
		 * This includes reading the abbreviation table address and the address
		 * size as, between the two versions, the order in which these two
		 * fields appear in the header was reversed for some reason. ¯\_(ツ)_/¯
		 */
		let version = cursor.read_u16::<Order>().map_err(repackage_eof)?;
		let (abbreviation_table, address_size) = if version == 5 {
			/* Check the unit type and see if we're compatible with it. */
			let unit_type = cursor.read_u8().map_err(repackage_eof)?;
			if unit_type != DW_UT_compile {
				return Err(Error::InvalidAbbreviationSection {
					source: anyhow!("unsupported unit type {} in header of \
					compilation unit {}",
					unit_type,
					compilation_unit)
				})
			}

			/* In version 5, we read the address size first, and the address of
			 * the abbreviation table first second. */
			let address_size = cursor.read_u8().map_err(repackage_eof)?;
			let abbreviation_table = cursor
				.read_uint::<Order>(compilation_unit.size_len())
				.map_err(repackage_eof)? as usize;

			(abbreviation_table, address_size)
		} else if version == 4 {
			/* In version 4, we read the address of the abbreviation table
			 * first, and the address size second. */
			let abbreviation_table = cursor
				.read_uint::<Order>(compilation_unit.size_len())
				.map_err(repackage_eof)? as usize;
			let address_size = cursor.read_u8().map_err(repackage_eof)?;

			(abbreviation_table, address_size)
		} else {
			/* We don't recognize anything other than 5 and 4. */
			return Err(Error::InvalidAbbreviationSection {
				source: anyhow!("unknown DWARF version {} in header of \
					compilation unit {}",
					version,
					compilation_unit)
			})
		};

		/* Figure out the offset of the first DIE and slice the reference. */
		let root_die_offset = cursor.position() as usize;
		let root_die_data = compilation_unit.slice(root_die_offset..).unwrap();

		/* Bootstrap the compilation unit state.
		 *
		 * We parse it from a structure pointing to the root DIE that uses a
		 * default version of the compilation state - that has bogus values.
		 * Since, in order to determine the values for it we won't need to look
		 * at any of the values that will be inside it once it's complete, there
		 * is no harm in doing it this way. */
		let state = CompilationUnitState::gather(
			&Die::new(
				CompilationUnitState::default(),
				abbreviation_table,
				address_size,
				root_die_data
			)?,
			abbreviation,
			strings,
			str_offsets,
			addr,
			rnglists
		)?;

		/* Build this compilation unit. */
		Ok(CompilationUnit {
			die_data: root_die_data,
			abbreviation_table,
			state,
			address_size,
			version,
			_bind: Default::default(),
		})
	}

	/// Get the root DIE of this compilation unit.
	pub fn root(&self) -> Result<Die<'a, Order>, Error> {
		Die::new(
			self.state,
			self.abbreviation_table,
			self.address_size,
			self.die_data
		)
	}

	/// Version of this compilation unit.
	pub fn version(&self) -> u16 {
		self.version
	}

	/// Value of `DW_AT_str_offsets_base`, if any.
	pub fn str_offsets_base(&self) -> Option<usize> {
		self.state.str_offsets_base
	}

	/// Value of `DW_AT_addr_base`, if any.
	pub fn addr_base(&self) -> Option<usize> {
		self.state.addr_base
	}

	/// Value of `DW_AT_rnglists_base`, if any.
	pub fn rnglists_base(&self) -> Option<usize> {
		self.state.rnglists_base
	}
}

/// Persistent values for all DIEs in a compilation unit.
///
/// A select number of attributes in a number of DIE tags can change the way we
/// interpret values of attributes in other DIEs in the same CU. This structure
/// exists to keep track of the value in those attributes so they can be used by
/// coding parsing the other DIEs.
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct CompilationUnitState {
	/// Base offset into the .debug_str_offsets section.
	str_offsets_base: Option<usize>,
	/// Base offset into the .debug_addr section.
	addr_base: Option<usize>,
	/// Base offset into the .debug_rnglists section.
	rnglists_base: Option<usize>
}
impl CompilationUnitState {
	pub fn gather<Order>(
		source_die: &Die<Order>,
		abbreviation: &AbbreviationIndex,
		strings: &StringsIndex,
		str_offsets: &StringOffsetsIndex<Order>,
		addr: Option<&AddressIndex<Order>>,
		rnglists: Option<&RangeListIndex<Order>>,
	) -> Result<Self, Error>
		where Order: ByteOrder {

		let mut this = CompilationUnitState::default();

		macro_rules! resolve_as {
			($attr:expr, $target:path, $name:expr) => {{
				match $attr.resolve(strings, str_offsets, addr, rnglists)? {
					$target(value) => value,
					other => return Err(Error::InvalidInfoSection {
						source: anyhow!("{} attribute of DIE {} has value of \
							unexpected type: {:?}",
							$name,
							source_die.attribute_data,
							other),
					})
				}
			}}
		}

		for attribute in source_die.attributes(abbreviation)? {
			let attribute = attribute?;
			match attribute.name() {
				/* Parse the string offsets table base offset for this
				 * compilation unit. The value is of form DW_FORM_sec_offset. */
				DW_AT_str_offsets_base =>
					this.str_offsets_base = Some(resolve_as!(
						attribute,
						AttributeValue::SectionOffset,
						"DW_AT_str_offsets_base"
					)),
				/* Parse the address table base offset for this compilation
				 * unit. The value is of form DW_FORM_sec_offset. */
				DW_AT_addr_base =>
					this.addr_base = Some(resolve_as!(
						attribute,
						AttributeValue::SectionOffset,
						"DW_AT_addr_base"
					)),
				/* Parse the range lists table base offset for this compilation
				 * unit. The value is of form DW_FORM_sec_offset. */
				DW_AT_rnglists_base =>
					this.rnglists_base = Some(resolve_as!(
						attribute,
						AttributeValue::SectionOffset,
						"DW_AT_rnglists_base"
					)),
				_ => { /* Ignore attributes we don't care about. */ }
			}
		}

		Ok(this)
	}
}

#[derive(Debug, Clone)]
pub struct Die<'a, Order: ByteOrder> {
	/// State affecting how we parse attributes in this DIE.
	state: CompilationUnitState,
	/// The length of the abbreviation code, used in determining how large the
	/// underlying data of this DIE in the debug info section is.
	abbreviation_code_len: usize,
	/// The abbreviation table the CU this DIE belongs to is using.
	abbreviation_table: usize,
	/// The code that uniquely identifies the abbreviation used by this DIE.
	abbreviation_code: AbbreviationCode,
	/// Tagged reference to the data backing this DIE.
	attribute_data: TaggedRef<'a>,
	/// How many bytes in an address value.
	address_size: u8,
	_bind: std::marker::PhantomData<Order>,
}
impl<'a, Order> Die<'a, Order>
	where Order: ByteOrder {

	/// Reads the abbreviation code of the DIE and builds a new structure, while
	/// doing no more validation than that which is needed to make sure the
	/// code can be read into an [`AbbreviationCode`] type.
	pub(crate) fn new(
		state: CompilationUnitState,
		abbreviation_table: usize,
		address_size: u8,
		data: TaggedRef<'a>,
	) -> Result<Self, Error> {
		/* Read the abbreviation code for this DIE. */
		let abbreviation_code = ULeb128::new(data.as_ref(), 0)
			.map_err(|what| Error::InvalidInfoSection {
				source: anyhow!("could not determine size of LEB128 \
					abbreviation code of DIE {}: {}",
					data,
					what),
			})?;
		let abbreviation_code_len = abbreviation_code.len();

		let abbreviation_code = abbreviation_code
			.try_into()
			.map_err(|what| Error::InvalidStringsSection {
				source: anyhow!("abbreviation code of DIE {} is too large to \
					fit in an AbbreviationCode value: {}",
					data,
					what),
			})?;

		Ok(Self {
			state,
			abbreviation_code_len,
			abbreviation_table,
			abbreviation_code,
			attribute_data: data.slice(abbreviation_code_len..).unwrap(),
			address_size,
			_bind: Default::default(),
		})
	}

	/// The length of all the attributes in this DIE, in bytes.
	fn attribute_len(
		&self,
		abbreviation: &AbbreviationIndex<'a>
	) -> Result<usize, Error> {
		if self.is_null() { return Ok(0) }

		/* We know the length ahead of time from whats in the abbreviation. */
		if let Some(len) = self.abbreviation(abbreviation)?
			.static_attributes_len() {
			return Ok(len)
		}

		/* We have to go the long way since one or more fields have variable
		 * size. */
		let mut len = 0;
		for attribute in self.attributes(abbreviation)? {
			let attribute = attribute?;
			len += attribute.len()?;
		}
		Ok(len)
	}

	/// The length of this DIE, in bytes, including the length of the
	/// abbreviation code and attributes. This is useful for the [`Descendants`]
	/// iterator.
	fn len(
		&self,
		abbreviation: &AbbreviationIndex<'a>
	) -> Result<usize, Error> {
		let attribute_len = self.attribute_len(abbreviation)?;
		Ok(self.abbreviation_code_len + attribute_len)
	}

	/// Whether this DIE is a NULL DIE.
	///
	/// # NULL DIEs
	///
	/// A DIE is said to be NULL when its abbreviation code is equal to zero,
	/// regardless of what abbreviation table value is in the compilation unit
	/// it belongs to. NULL DIEs are used to signal the end of sibling chains
	/// as well as to pad out space at the end of the section.
	///
	/// While it is not invalid to construct a [`Die`] structure from a NULL
	/// DIE, doing so will yield a structure in which most of functionality
	/// is inaccessible.
	pub fn is_null(&self) -> bool {
		self.abbreviation_code == 0
	}

	/// Gather the abbreviation value of this DIE.
	///
	/// # Panic
	///
	/// This function will panic if this is a NULL DIE, as indicated by
	/// [`Die::is_null`].
	pub fn abbreviation<'b>(
		&self,
		abbreviation: &'b AbbreviationIndex<'a>
	) -> Result<&'b Abbreviation, Error> {
		if self.is_null() {
			panic!("called the abbreviation() function of a NULL DIE")
		}

		abbreviation
			.get(
				self.abbreviation_table,
				self.abbreviation_code
			).ok_or_else(|| Error::InvalidInfoSection {
				source: anyhow!("DIE {} has invalid abbreviation key: \
					0x{:016x}/{}",
					self.attribute_data,
					self.abbreviation_table,
					self.abbreviation_code),
			})
	}

	/// Get an iterator over the attributes in this DIE.
	///
	/// # Panic
	///
	/// This function will panic if this is a NULL DIE, as indicated by
	/// [`Die::is_null`].
	pub fn attributes<'b>(
		&'b self,
		abbreviation: &'b AbbreviationIndex<'a>
	) -> Result<Attributes<'b, 'a, Order>, Error> {
		if self.is_null() {
			panic!("called the attributes() function of a NULL DIE")
		}

		Ok(Attributes {
			die: self,
			abbrev: self.abbreviation(abbreviation)?.attributes(),
			offset: 0,
			failed: false,
		})
	}

	/// Whether this DIE has any children.
	///
	/// # Panic
	///
	/// This function will panic if this is a NULL DIE, as indicated by
	/// [`Die::is_null`].
	pub fn has_children(
		&self,
		abbreviation: &AbbreviationIndex<'a>
	) -> Result<bool, Error> {
		if self.is_null() {
			panic!("called the has_children() function of a NULL DIE")
		}

		let abbreviation = self.abbreviation(abbreviation)?;
		Ok(abbreviation.has_children())
	}

	/// Get an iterator over all DIE that descend from this DIE.
	///
	/// # Panic
	///
	/// This function will panic if this is a NULL DIE, as indicated by
	/// [`Die::is_null`].
	pub fn descendants<'b>(
		&'b self,
		abbreviation: &'b AbbreviationIndex<'a>
	) -> Result<Descendants<'b, 'a, Order>, Error> {
		if self.is_null() {
			panic!("called the descendants() function of a NULL DIE")
		}
		let attributes_len = self.attribute_len(abbreviation)?;
		Ok(Descendants {
			parent: self,
			abbreviation,
			current_ref: self.attribute_data.slice(attributes_len..)
				.ok_or_else(|| Error::InvalidInfoSection {
					source: anyhow!("cannot initialize iterator reference of \
						DIE at {} by skipping {} attribute bytes",
						self.attribute_data,
						attributes_len),
				})?,
			stopped: !self.has_children(abbreviation)?,
			depth: 0,
		})
	}

	/// Get an iterator over the children elements of this DIE.
	///
	/// # Panic
	///
	/// This function will panic if this is a NULL DIE, as indicated by
	/// [`Die::is_null`].
	pub fn children<'b>(
		&'b self,
		abbreviation: &'b AbbreviationIndex<'a>,
	) -> Result<Children<'b, 'a, Order>, Error> {
		Ok(Children {
			descendants: self.descendants(abbreviation)?,
		})
	}
}

/// Iterator over the direct children of a [`Die`].
pub struct Children<'a, 'b, Order: ByteOrder> {
	descendants: Descendants<'a, 'b, Order>
}
impl<'a, 'b, Order> Iterator for Children<'a, 'b, Order>
	where Order: ByteOrder {

	type Item = Result<Die<'b, Order>, Error>;
	fn next(&mut self) -> Option<Self::Item> {
		/* Only yield elements that are non-null and that are direct children
		 * of the DIE (depth == 0), otherwise, just move through it. */
		loop {
			let (depth, die) = match self.descendants.next()? {
				Ok(next) => next,
				Err(what) => return Some(Err(what))
			};
			if depth == 0 && !die.is_null() { break Some(Ok(die)) }
		}
	}
}

/// Iterator over the elements descending from a [`Die`].
pub struct Descendants<'a, 'b, Order: ByteOrder> {
	parent: &'a Die<'b, Order>,
	abbreviation: &'a AbbreviationIndex<'b>,
	current_ref: TaggedRef<'b>,
	stopped: bool,
	depth: u64,
}
impl<'a, 'b, Order> Iterator for Descendants<'a, 'b, Order>
	where Order: ByteOrder {

	type Item = Result<(u64, Die<'b, Order>), Error>;
	fn next(&mut self) -> Option<Self::Item> {
		if self.stopped { return None }

		/* Build the DIE currently at the reference. */
		let die = Die::new(
			self.parent.state,
			self.parent.abbreviation_table,
			self.parent.address_size,
			self.current_ref);
		let die = iter_bail_early!(self.stopped, die);
		let die_depth = self.depth;

		/* Figure out how many bytes until the next entry. */
		let len = iter_bail_early!(self.stopped, die.len(self.abbreviation));

		/* Check if the next entry is a child of this entry, a sibling, or the
		 * sibling of a parent and adjust the depth parameter if needed. */
		if die.is_null() {
			/* If this is the last DIE of depth zero, stop the iterator,
			 * otherwise just record that we've moved up a depth of the tree. */
			if self.depth == 0 {
				self.stopped = true;
			} else {
				self.depth -= 1;
			}
		} else {
			/* Distinguish between the sibling and child cases. */
			if iter_bail_early!(self.stopped, die.has_children(self.abbreviation)) {
				self.depth += 1
			}
		}

		/* Try to advance the tagged reference to the next DIE. */
		let next_ref = self.current_ref.slice(len..)
			.ok_or_else(|| Error::InvalidInfoSection {
				source: anyhow!("cannot advance child iterator reference \
					{} of DIE at {} by the length of its child of {} bytes",
					self.current_ref,
					self.parent.attribute_data,
					len),
			});
		self.current_ref = iter_bail_early!(self.stopped, next_ref);

		Some(Ok((die_depth, die)))
	}
}

/// Iterator over the attributes of a [`Die`].
pub struct Attributes<'a, 'b, Order: ByteOrder> {
	die: &'a Die<'b, Order>,
	abbrev: std::slice::Iter<'a, AbbreviationAttribute>,
	offset: usize,
	failed: bool,
}
impl<'a, 'b, Order> Iterator for Attributes<'a, 'b, Order>
	where Order: ByteOrder {

	type Item = Result<Attribute<'a, 'b, Order>, Error>;
	fn next(&mut self) -> Option<Self::Item> {
		if self.failed { return None }

		let abbrev = self.abbrev.next()?;
		let next = Attribute {
			die: self.die,
			abbrev: abbrev.clone(),
			data: self.die.attribute_data.slice(self.offset..)?,
		};
		self.offset += iter_bail_early!(self.failed, next.len());
		Some(Ok(next))
	}
}

pub struct Attribute<'a, 'b, Order: ByteOrder> {
	/// Reference to the DIE this attribute belongs to.
	die: &'a Die<'b, Order>,
	/// Abbreviation information which describes the data in the attribute.
	abbrev: AbbreviationAttribute,
	/// Tagged reference to the beginning of the attribute.
	data: TaggedRef<'b>,
}
impl<'a, 'b, Order> Attribute<'a, 'b, Order>
	where Order: ByteOrder {

	/// Name of this attribute.
	pub fn name(&self) -> AttributeName {
		self.abbrev.name
	}

	/// Length of this attribute, in bytes.
	pub fn len(&self) -> Result<usize, Error> {
		/* Bail early in case the form of this attribute has a static length. */
		if let Some(len) = static_form_len(self.abbrev.form) {
			return Ok(len)
		}

		Ok(match self.abbrev.form {
			DW_FORM_string =>
				CStr::from_bytes_until_nul(&self.data.as_ref())
					.map_err(|what| Error::InvalidInfoSection {
						source: anyhow!("could not determine size of \
							DW_FORM_string value at {}: {}",
							self.data,
							what),
					})?
					.to_bytes_with_nul()
					.len(),

			/* From the point of view of readability, it makes no sense to use
			 * `ULeb128` to figure out how large `DW_FORM_sdata` is. While the
			 * results will be correct (byte length is encoded the same in both
			 * the signed and unsigned variants of LEB128), if you are reading
			 * this without prior knowledge, you might reasonably assume
			 * `DW_FORM_sdata` is somehow tied to ULeb128 when that is most
			 * definitely _not_ the case.
			 *
			 * TODO: `DW_FORM_sdata` should use ILeb128. */
			DW_FORM_addrx | DW_FORM_strx | DW_FORM_sdata | DW_FORM_udata
				| DW_FORM_ref_udata | DW_FORM_rnglistx | DW_FORM_loclistx =>
				ULeb128::new(self.data.as_ref(), 0)
					.map_err(|what| Error::InvalidInfoSection {
						source: anyhow!("could not determine size of LEB128 \
							value of attribute at {}: {}",
							self.data,
							what),
					})?
					.len(),

			/* Expression are inline right after their length. */
			DW_FORM_exprloc => {
				let expr_len_enc = ULeb128::new(self.data.as_ref(), 0)
					.map_err(|what| Error::InvalidInfoSection {
						source: anyhow!("could not determine size of LEB128 \
							value of DW_FORM_exprloc attribute at {}: {}",
							self.data,
							what),
					})?;
				let expr_len: u64 = expr_len_enc.try_into()
					.map_err(|what| Error::InvalidInfoSection {
						source: anyhow!("DW_FORM_exprloc size value at {} is \
							too large to fit in a u64 value",
							self.data),
					})?;

				expr_len_enc.len() + expr_len as usize
			}


			DW_FORM_strp | DW_FORM_line_strp | DW_FORM_strp_sup
				| DW_FORM_sec_offset | DW_FORM_ref_addr =>
				self.data.size_len(),

			DW_FORM_addr => usize::from(self.die.address_size),

			form => panic!("form type 0x{:04x} is not implemented for len()", form)
		})
	}

	/// Resolve the value of the
	pub fn resolve(
		&self,
		strings: &StringsIndex<'b>,
		str_offsets: &StringOffsetsIndex<'b, Order>,
		addr: Option<&AddressIndex<'a, Order>>,
		rnglists: Option<&RangeListIndex<'b, Order>>,
	) -> Result<AttributeValue<'b, Order>, Error> {


		Ok(match self.abbrev.form {
			/* DW_FORM_string indicates inline string data. */
			DW_FORM_string => AttributeValue::String(
				CStr::from_bytes_until_nul(self.data.inner())
					.map_err(|what| Error::InvalidInfoSection {
						source: anyhow!("could not determine value of \
							DW_FORM_string value at {}: {}",
							self.data,
							what),
					})?),
			/* DW_FORM_strp has an offset to the strings section. */
			DW_FORM_strp => {
				let mut cursor = Cursor::new(self.data.as_ref());
				let offset = cursor.read_uint::<Order>(self.data.size_len())
					.map_err(repackage_eof)?;
				let offset = offset as usize;

				let string = strings.get(offset)
					.ok_or_else(|| Error::InvalidInfoSection {
						source: anyhow!("could not find a string beginning at \
							offset 0x{:016x} of the strings section for value of \
							form DW_FORM_strp at {}",
							offset,
							self.data),
					})?;

				AttributeValue::String(string)
			},
			/* For the DW_FORM_strx family, there is an extra level of
			 * indirection we have to go through before we get our string. */
			DW_FORM_strx | DW_FORM_strx1 | DW_FORM_strx2 | DW_FORM_strx3 | DW_FORM_strx4 => {
				let mut cursor = Cursor::new(self.data.as_ref());
				let index: StringOffsetsSetIndex = match self.abbrev.form {
					DW_FORM_strx =>
						ULeb128::new(self.data.as_ref(), 0)
							.map_err(|what| Error::InvalidInfoSection {
								source: anyhow!("could not determine size of \
									DW_FORM_strx LEB128 value at {}: {}",
									self.data,
									what),
							})?
							.try_into()
							.map_err(|what| Error::InvalidInfoSection {
								source: anyhow!("DW_FORM_strx value at {} is \
									too large to fit in a StringOffsetsIndex \
									value: {}",
									self.data,
									what),
							})?,
					DW_FORM_strx1 =>
						cursor.read_uint::<Order>(1).map_err(repackage_eof)?
							as StringOffsetsSetIndex,
					DW_FORM_strx2 =>
						cursor.read_uint::<Order>(2).map_err(repackage_eof)?
							as StringOffsetsSetIndex,
					DW_FORM_strx3 =>
						cursor.read_uint::<Order>(3).map_err(repackage_eof)?
							as StringOffsetsSetIndex,
					DW_FORM_strx4 =>
						cursor.read_uint::<Order>(4).map_err(repackage_eof)?
							as StringOffsetsSetIndex,
					_ => unreachable!()
				};

				let base = self.die.state.str_offsets_base
					.ok_or_else(|| Error::InvalidInfoSection {
						source: anyhow!("DW_FORM_strx value at {} used in a \
							DIE from a compilation unit that has no value for \
							DW_AT_str_offsets_base",
							self.data),
					})?;

				let offset = str_offsets.get(base, index)
					.ok_or_else(|| Error::InvalidInfoSection {
						source: anyhow!("set 0x{:016x} index 0x{:08x} does not \
							name a valid entry in the string offsets section, \
							while trying to get value of an DW_FORM_strx \
							attribute at {}",
							base,
							index,
							self.data),
					})?;

				let string = strings.get(offset)
					.ok_or_else(|| Error::InvalidInfoSection {
						source: anyhow!("could not find a string beginning at \
							offset 0x{:016x} of the strings section for value of \
							form DW_FORM_strx at {}",
							offset,
							self.data),
					})?;

				AttributeValue::String(string)
			}
			/* DW_FORM_sec_offset is simply a usize value. */
			DW_FORM_sec_offset =>
				AttributeValue::SectionOffset(
					Cursor::new(self.data.as_ref())
						.read_uint::<Order>(self.data.size_len())
						.map_err(repackage_eof)? as usize
				),
			/* DW_FORM_addr is an unsigned integer with as many bytes as the
			 * size type of the target architecture. */
			DW_FORM_addr =>
				AttributeValue::Address(Address::from(
					Cursor::new(self.data.as_ref())
						.read_uint::<Order>(usize::from(self.die.address_size))
						.map_err(repackage_eof)?
				)),
			/* For the DW_FORM_addrx family, there is an extra level of
			 * indirection we have to go through before we get our address. */
			DW_FORM_addrx | DW_FORM_addrx1 | DW_FORM_addrx2 | DW_FORM_addrx3 | DW_FORM_addrx4 => {
				let mut cursor = Cursor::new(self.data.as_ref());
				let index: AddressSetIndex = match self.abbrev.form {
					DW_FORM_addrx =>
						ULeb128::new(self.data.as_ref(), 0)
							.map_err(|what| Error::InvalidInfoSection {
								source: anyhow!("could not determine size of \
									DW_FORM_addrx LEB128 value at {}: {}",
									self.data,
									what),
							})?
							.try_into()
							.map_err(|what| Error::InvalidInfoSection {
								source: anyhow!("DW_FORM_addrx value at {} is \
									too large to fit in an AddressSetIndex \
									value: {}",
									self.data,
									what),
							})?,
					DW_FORM_addrx1 =>
						cursor.read_uint::<Order>(1).map_err(repackage_eof)?
							as AddressSetIndex,
					DW_FORM_addrx2 =>
						cursor.read_uint::<Order>(2).map_err(repackage_eof)?
							as AddressSetIndex,
					DW_FORM_addrx3 =>
						cursor.read_uint::<Order>(3).map_err(repackage_eof)?
							as AddressSetIndex,
					DW_FORM_addrx4 =>
						cursor.read_uint::<Order>(4).map_err(repackage_eof)?
							as AddressSetIndex,
					_ => unreachable!()
				};

				let base = self.die.state.addr_base
					.ok_or_else(|| Error::InvalidInfoSection {
						source: anyhow!("DW_FORM_addrx value at {} used in a \
							DIE from a compilation unit that has no value for \
							DW_AT_addr_base",
							self.data),
					})?;

				let addr = addr
					.ok_or_else(|| Error::InvalidInfoSection {
						source: anyhow!("DW_FORM_addrx value at {} used in \
							DWARF file with no .debug_addr section",
							self.data),
					})?;

				let address = addr.get(base, index)
					.ok_or_else(|| Error::InvalidInfoSection {
						source: anyhow!("set 0x{:016x} index 0x{:08x} does not \
							name a valid entry in the address section, \
							while trying to get value of an DW_FORM_addrx \
							attribute at {}",
							base,
							index,
							self.data),
					})?;

				AttributeValue::Address(address)
			},
			/* For the DW_FORM_rnglistx form, we index into the rnglists. */
			DW_FORM_rnglistx => {
				let index: RangeListOffsetsIndex = ULeb128::new(self.data.as_ref(), 0)
					.map_err(|what| Error::InvalidInfoSection {
						source: anyhow!("could not determine size of \
							DW_FORM_rnglistx LEB128 value at {}: {}",
							self.data,
							what),
					})?
					.try_into()
					.map_err(|what| Error::InvalidInfoSection {
						source: anyhow!("DW_FORM_rnglistx value at {} is too \
							large to fit in a RangeListOffsetsIndex value: {}",
							self.data,
							what),
					})?;

				let base = self.die.state.rnglists_base
					.ok_or_else(|| Error::InvalidInfoSection {
						source: anyhow!("DW_FORM_rnglistx value at {} used in \
							a DIE from a compilation unit that has no value \
							for DW_AT_rnglists_base",
							self.data),
					})?;

				let rnglists = rnglists
					.ok_or_else(|| Error::InvalidInfoSection {
						source: anyhow!("DW_FORM_rnglistx value at {} used in \
							DWARF file with no .debug_rnglists section",
							self.data),
					})?;

				let range_list = rnglists.get(base, index)
					.ok_or_else(|| Error::InvalidInfoSection {
						source: anyhow!("could not find a range list based at \
							0x{:016x} and of index {} for value of form \
							DW_FORM_rnglistx at {}",
							base,
							index,
							self.data),
					})?;

				AttributeValue::RangeList(range_list)
			}

			form => panic!("form type 0x{:04x} is not implemented for resolve()", form)
		})
	}
}

/// Returns the length in bytes of the given form, if it is static.
///
/// # Static and non-static form lengths
/// In DWARF, the values of some forms have their byte size fixed ahead of time
/// by the specification, while values of other forms have variable sizes. This
/// means that, for some forms, we need no information other than its name to
/// know how large its value will be.
///
/// As a consequence of that, and of particular interest to us, a DIE can have
/// its inner length determined entirely ahead of time if its abbreviation is
/// made up entirely of forms with static lengths.
///
pub fn static_form_len(form: FormName) -> Option<usize> {
	Some(match form {
		DW_FORM_addrx1 | DW_FORM_data1 | DW_FORM_strx1 | DW_FORM_ref1
			| DW_FORM_flag => 1,
		DW_FORM_addrx2 | DW_FORM_data2 | DW_FORM_strx2 | DW_FORM_ref2 => 2,
		DW_FORM_addrx3 | DW_FORM_strx3 => 3,
		DW_FORM_addrx4 | DW_FORM_data4 | DW_FORM_strx4 | DW_FORM_ref4
			| DW_FORM_ref_sup4 => 4,
		DW_FORM_data8 | DW_FORM_ref8 | DW_FORM_ref_sig8 | DW_FORM_ref_sup8 => 8,
		DW_FORM_data16 => 16,

		/* Information for these is stored elsewhere, so they have no size in
		 * the actual DIE. */
		DW_FORM_flag_present | DW_FORM_implicit_const => 0,

		/* We either don't know of this form, or its size has to be determined
		 * at time of parsing. */
		_ => return None
	})
}

#[derive(Debug)]
pub enum AttributeValue<'a, Order: ByteOrder> {
	/// Values of form DW_FORM_string and DW_FORM_strx.
	String(&'a CStr),
	/// Values of form DW_FORM_addr and DW_FORM_addrx.
	Address(Address),
	/// Values of form DW_FORM_sec_offset.
	SectionOffset(usize),
	/// Values of form DW_FORM_rnglistx.
	RangeList(RangeList<'a, Order>),
}