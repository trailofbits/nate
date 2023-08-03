use std::collections::{BTreeMap, HashMap};
use std::ffi::CStr;
use std::io::Cursor;
use anyhow::anyhow;
use byteorder::{ByteOrder, ReadBytesExt};
use crate::{DwarfSections, Error};
use crate::types::{StringOffsetsSetIndex, TaggedRef};

pub struct StringsIndex<'a> {
	/// We only really save a reference to the strings section here, as scanning
	/// strings is expensive and stalls startup, we can build the index lazily
	/// on a per-thread basis.
	strings: &'a [u8]
}
impl<'a> StringsIndex<'a> {
	pub fn new(sections: &DwarfSections<'a>) -> Result<Self, Error> {
		Ok(Self {
			strings: sections.str
		})
	}

	pub fn get(&self, index: usize) -> Option<&'a CStr> {
		/* We don't want to support substrings here. */
		if index > 0 && self.strings[index - 1] != 0 { return None }

		CStr::from_bytes_until_nul(&self.strings[index..]).ok()
	}
}

pub struct StringOffsetsIndex<'a, Order: ByteOrder> {
	index: BTreeMap<usize, TaggedRef<'a>>,
	_bind: std::marker::PhantomData<Order>
}
impl<'a, Order: ByteOrder> StringOffsetsIndex<'a, Order> {
	pub fn new(sections: &DwarfSections<'a>) -> Result<Self, Error> {
		let str_offsets = sections.str_offsets;

		let mut index = BTreeMap::default();
		let mut cursor = Cursor::new(str_offsets);

		while let Some((offset_to_header, unit_ref)) =
			TaggedRef::try_next_from_cursor::<Order>(&mut cursor)? {

			if unit_ref.as_ref().len() < 4 {
				return Err(Error::InvalidStringOffsetsSection {
					source: anyhow!("string offsets set at 0x{:016x} ends \
						unexpectedly (missing header fields)",
						offset_to_header),
				})
			} else if (unit_ref.as_ref().len() - 4) % unit_ref.size_len() != 0 {
				return Err(Error::InvalidStringOffsetsSection {
					source: anyhow!("string offsets set at 0x{:016x} ends \
						unexpectedly (non-whole number of entries)",
						offset_to_header),
				})
			}

			let mut cursor = Cursor::new(unit_ref.as_ref());
			let version = cursor.read_u16::<Order>().unwrap();
			let reserved = cursor.read_u16::<Order>().unwrap();

			let offset_to_first_entry = cursor.position() as usize;

			if version != 5 {
				return Err(Error::InvalidStringOffsetsSection {
					source: anyhow!("string offsets set at 0x{:016x} is of \
						unknown version {}",
						offset_to_header,
						version)
				})
			} else if reserved != 0 {
				return Err(Error::InvalidStringOffsetsSection {
					source: anyhow!("string offsets set at 0x{:016x} has \
						unknown value for reserved field 0x{:04x}",
						offset_to_header,
						reserved)
				})
			}


			index.insert(
				offset_to_header + offset_to_first_entry,
				unit_ref.slice(offset_to_first_entry..).unwrap());
		}

		Ok(Self {
			index,
			_bind: Default::default(),
		})
	}

	/// Get the offset into the debug strings section pointed to by a entry of
	/// the given index in the set with a given `DW_AT_str_offsets_base` value.
	pub fn get(&self,
		base: usize,
		index: StringOffsetsSetIndex
	) -> Option<usize> {
		self.index.range(..=base)
			.last()
			.and_then(|(actual_base, set)| {
				let delta = base - actual_base;
				if delta % set.size_len() != 0 {
					/* This offset is bogus. Offsets must point to the beginning
					 * of an entry, and this one points to the middle of one. */
					return None
				}

				let index = index
					+ (delta / set.size_len()) as StringOffsetsSetIndex;
				Self::index_into_set(*set, index)
			})
	}

	fn index_into_set(
		set: TaggedRef<'a>,
		index: StringOffsetsSetIndex
	) -> Option<usize> {
		let data = set.as_ref();
		let entry_size = set.size_len();

		let mut cursor = Cursor::new(data.get(entry_size * index as usize..)?);
		Some(cursor.read_uint::<Order>(entry_size).unwrap() as usize)
	}
}
