use std::fmt::Formatter;
use std::io::{Cursor, Seek};
use std::ops::RangeBounds;
use anyhow::anyhow;
use byteorder::{ByteOrder, ReadBytesExt};
use crate::Error;

/// Attribute names have a maximum value of 0x3fff.
pub type AttributeName = u16;

/// Form names have a maximum value of 0x2c.
pub type FormName = u8;

/// Operation names have a maximum value of 0xff.
pub type OperationName = u8;

/// Language names have a maximum value of 0xffff.
pub type LanguageName = u16;

/// Tag names have a maximum value of 0xffff.
pub type TagName = u16;

/// Indexes into a set in the string offsets table can be at most 4 bytes long.
pub type StringOffsetsSetIndex = u32;

/// Indexes into a set in the addresses table can be at most 4 bytes long.
pub type AddressSetIndex = u32;

/// The entry count is 4 bytes long, we can't have more than a u32's worth of
/// indexes into a range list offsets array.
pub type RangeListOffsetsIndex = u32;

/// Type that can house all of the addresses we support.
pub type Address = u64;

/// Stops iteration and returns a last `Some(Err(_))` in case of an error.
///
/// This is a common enough operation throughout this crate (pretty much all
/// fallible iterators use it) that it makes sense for us to separate it into
/// its own thing.
macro_rules! iter_bail_early_impl {
	($target:expr, $value:expr) => {{
		match $value {
			Ok(value) => value,
			Err(what) => {
				$target = true;
				return Some(Err(what))
			}
		}
	}}
}
pub(crate) use iter_bail_early_impl as iter_bail_early;

/// Enum containing all DWARF formats. See [`TaggedRef`] for more information.
///
/// [`TaggedRef`]: TaggedRef
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum DwarfFormat {
	/// The 32-bit DWARF format.
	Dwarf32,
	/// The 64-bit DWARF format.
	Dwarf64,
}

/// Helps keep track of where tagged references are pointing. This helps improve
/// diagnostics immensely, but may use more memory than is desirable.
#[cfg(feature = "tagged-ref-diagnostic-tracking")]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct TaggedRefTracking {
	/// Offset of the cursor when the base reference was created.
	cursor_base: u64,
	/// Offset of the current slice relative to the start of the object.
	offset: usize,
}

/// Format-distinguishing reference to a slice containing the data for a DWARF
/// object.
///
/// # Formats
/// Many kinds of objects in DWARF 5 may be in one of two formats, the 32-bit
/// DWARF one or the 64-bit DWARF one, and, since parsing the length of a given
/// object by necessity also tells us which format that object is in, we can
/// avoid doing this work more than once.
///
#[derive(Debug, Copy, Clone)]
pub struct TaggedRef<'a> {
	/// The format this reference is in.
	format: DwarfFormat,
	/// The slice backing this reference.
	slice: &'a [u8],

	/// Tracking information.
	#[cfg(feature = "tagged-ref-diagnostic-tracking")]
	tracking: TaggedRefTracking,
}
impl<'a> AsRef<[u8]> for TaggedRef<'a> {
	fn as_ref(&self) -> &[u8] {
		self.slice
	}
}
impl<'a> TaggedRef<'a> {
	/// Returns the slice backing up this reference, while preserving its lifetime.
	pub fn inner(&self) -> &'a [u8] {
		self.slice
	}

	/// Slice this reference into a sub range, preserving format information.
	pub fn slice<R>(&self, range: R) -> Option<TaggedRef<'a>>
		where R: RangeBounds<usize> {

		let range = (range.start_bound().cloned(), range.end_bound().cloned());
		let slice = self.slice.get(range)?;
		Some(Self {
			format: self.format,
			slice,
			#[cfg(feature = "tagged-ref-diagnostic-tracking")]
			tracking: TaggedRefTracking {
				cursor_base: self.tracking.cursor_base,
				offset: self.tracking.offset + (self.slice.len() - slice.len()),
			},
		})
	}

	/// The number of bytes in a size-dependent integer value for this format.
	pub fn size_len(&self) -> usize {
		match self.format {
			DwarfFormat::Dwarf32 => 4,
			DwarfFormat::Dwarf64 => 8
		}
	}

	/// Try to parse the next reference from the given cursor and return the
	/// offset of the first byte after the initial size field as well as the
	/// tagged reference.
	pub fn try_next_from_cursor<Order: ByteOrder>(
		cursor: &mut Cursor<&'a [u8]>
	) -> Result<Option<(usize, TaggedRef<'a>)>, Error> {
		Ok(Self::try_next_from_cursor_with_size::<Order>(cursor)?
			.map(|(offset, _, tagged_ref)| (offset, tagged_ref)))
	}

	/// Try to parse the next reference from the given cursor and return the
	/// offset of the first byte after the initial size field as well as the
	/// size of the object pointed to by the reference, and the reference
	/// itself.
	pub fn try_next_from_cursor_with_size<Order: ByteOrder>(
		cursor: &mut Cursor<&'a [u8]>
	) -> Result<Option<(usize, usize, TaggedRef<'a>)>, Error> {
		let info = cursor.get_ref();

		/* Return None if there is no more data left in the cursor. */
		if cursor.position() >= info.len() as u64 {
			return Ok(None)
		}

		/* Constructs a new slice of `info` beginning at the position of the cursor,
		 * and having size `len`. Errors out if the slice wouldn't fit in `info`,
		 * otherwise advances the cursor by `len`. */
		let read_slice = |cursor: &mut Cursor<&'a [u8]>, len| {
			let base = cursor.position() as usize;
			let slice = info.get(base..base + len);
			match slice {
				Some(slice) => {
					cursor.seek(std::io::SeekFrom::Current(len as i64)).unwrap();
					Ok((base, slice))
				},
				None => return Err(Error::InvalidAbbreviationSection {
					source: anyhow!("length 0x{:x} of object at 0x{:016x} is \
						longer than the section",
						len,
						base),
				})
			}
		};

		/* Parse the initial length field and build a new reference. */
		let initial_len = cursor.read_u32::<Order>().map_err(repackage_eof)?;
		Ok(match initial_len {
			0xffffffff => {
				/* This is a 64-bit entry. */
				let len = cursor.read_u64::<Order>()
					.map_err(repackage_eof)?;
				let len = len as usize;

				let (base, slice) = read_slice(cursor, len)?;
				Some((base, len, Self {
					format: DwarfFormat::Dwarf64,
					slice,
					#[cfg(feature = "tagged-ref-diagnostic-tracking")]
					tracking: TaggedRefTracking {
						cursor_base: base as u64,
						offset: 0,
					}
				}))
			},
			len if len < 0xfffffff0 => {
				/* This is a 32-bit entry. */
				let len = len as usize;
				let (base, slice) = read_slice(cursor, len)?;
				Some((base, len, Self {
					format: DwarfFormat::Dwarf32,
					slice,
					#[cfg(feature = "tagged-ref-diagnostic-tracking")]
					tracking: TaggedRefTracking {
						cursor_base: base as u64,
						offset: 0,
					}
				}))
			}
			reserved =>
				return Err(Error::InvalidInfoSection {
					source: anyhow!(
					"unknown reserved initial length value 0x{:08x} of object \
					at offset 0x{:016x}",
					reserved,
					cursor.position()),
				})
		})
	}
}
impl std::fmt::Display for TaggedRef<'_> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		#[cfg(not(feature = "tagged-ref-diagnostic-tracking"))]
		{
			write!(f, "[TaggedRef addr=0x{:016x} len=0x{:016x}]",
				self.slice.as_ptr() as usize,
				self.slice.len())
		}
		#[cfg(feature = "tagged-ref-diagnostic-tracking")]
		{
			write!(f, "[TaggedRef addr=0x{:016x} len=0x{:016x} \
				base_offset=0x{:016x} elem_offset=0x{:016x}]",
				self.slice.as_ptr() as usize,
				self.slice.len(),
				self.tracking.cursor_base,
				self.tracking.cursor_base + self.tracking.offset as u64)
		}
	}
}

/// Take an I/O error produced by the cursor and repackage it in case of an EOF
/// so we can signal the user the data in the info section ended sooner than we
/// expected, and panic on other kinds of I/O errors.
pub fn repackage_eof(what: std::io::Error) -> Error {
	if let std::io::ErrorKind::UnexpectedEof = what.kind() {
		Error::InvalidInfoSection {
			source: anyhow!("section data ends unexpectedly: {}", what),
		}
	} else {
		panic!(
			"unexpected i/o error when reading from section data cursor: {}",
			what
		)
	}
}