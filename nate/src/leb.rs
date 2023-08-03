use std::io::{Cursor, Seek, SeekFrom};

#[derive(Debug, Copy, Clone)]
pub struct ULeb128<'a> {
	ptr: &'a [u8],
}
impl<'a> ULeb128<'a> {
	pub fn next_from_cursor(
		cursor: &mut Cursor<&'a [u8]>
	) -> Result<Self, UnexpectedEndOfBuffer> {
		let base = *cursor.get_ref();
		let offset = cursor.position() as usize;
		let next = Self::new(base, offset)?;
		
		cursor.seek(SeekFrom::Current(next.len() as i64)).unwrap();
		
		Ok(next)
	}
	
	pub fn new(base: &'a [u8], offset: usize) -> Result<Self, UnexpectedEndOfBuffer> {
		if offset >= base.len() {
			return Err(UnexpectedEndOfBuffer)
		}

		let base = base.get(offset..).ok_or(UnexpectedEndOfBuffer)?;
		let (last, _) = base.iter()
			.enumerate()
			.find(|(_, byte)| *byte & 0x80 == 0)
			.ok_or(UnexpectedEndOfBuffer)?;

		Ok(Self {
			ptr: &base[..=last],
		})
	}

	pub fn is_zero(&self) -> bool {
		self.ptr[0] == 0
	}

	pub fn bits(&self) -> u32 {
		let len = self.len();
		let trailing = self.ptr[len - 1];
		let trailing = u8::BITS - trailing.leading_zeros();

		(len as u32 - 1) * 7 + trailing
	}

	pub fn len(&self) -> usize {
		self.ptr.len()
	}

	pub fn bytes(&self) -> impl Iterator<Item = u8> + 'a {
		self.ptr.iter().cloned()
	}
}

#[derive(Debug, thiserror::Error)]
#[error("the backing slice ends before the LEB128 value")]
pub struct UnexpectedEndOfBuffer;

#[derive(Debug, thiserror::Error)]
#[error("the target integer is too narrow for this LEB128 value")]
pub struct TargetIntegerTooNarrow;

macro_rules! implement_conversion_to {
	(target: $target:ty) => {
		impl<'a> TryFrom<ULeb128<'a>> for $target {
			type Error = TargetIntegerTooNarrow;
			fn try_from(value: ULeb128<'a>) -> Result<Self, Self::Error> {
				/* Do a quicker, coarse check, to see if, no matter what the
				 * number in the last byte is, we are sure the whole number will
				 * fit in the target integer.
				 *
				 * In real-world DWARF data this case is by far the most common,
				 * and so it makes sense to separate it into its own thing, as
				 * ULEB128 code is often in the hot path. */
				let quick_in_bounds = ((value.len() * 7) as u32) < <$target>::BITS;

				/* If we aren't sure yet - eg. if it could potentially fit if
				 * the number in the last byte is small enough, do a fine check
				 * to see it will fit. */
				if !quick_in_bounds && value.bits() > <$target>::BITS {
					return Err(TargetIntegerTooNarrow)
				}

				let mut target: $target = 0;
				let mut counter = 0;
				for byte in value.bytes() {
					target |= ((byte & 0x7f) as $target) << (7 * counter);
					counter += 1;
				}

				Ok(target as $target)
			}
		}
	}
}

implement_conversion_to! { target: u64 }
implement_conversion_to! { target: u32 }
implement_conversion_to! { target: u16 }
implement_conversion_to! { target: u8 }
