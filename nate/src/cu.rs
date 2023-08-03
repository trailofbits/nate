use std::collections::HashMap;
use std::io::Cursor;
use byteorder::ByteOrder;
use rayon::iter::{ParallelIterator, IntoParallelIterator, IntoParallelRefIterator};
use crate::die::CompilationUnit;
use crate::{DwarfSections, Error};
use crate::abbreviation::AbbreviationIndex;
use crate::address::{AddressIndex, RangeListIndex};
use crate::str::{StringOffsetsIndex, StringsIndex};
use crate::types::TaggedRef;

pub struct CompilationUnitIndex<'a, Order: ByteOrder> {
	index: HashMap<usize, CompilationUnit<'a, Order>, ahash::RandomState>,
}
impl<'a, Order> CompilationUnitIndex<'a, Order>
	where Order: ByteOrder + Send + Sync {

	pub fn new(
		sections: &DwarfSections<'a>,
		abbreviation: &AbbreviationIndex<'a>,
		strings: &StringsIndex<'a>,
		str_offsets: &StringOffsetsIndex<'a, Order>,
		addr: Option<&AddressIndex<'a, Order>>,
		rnglists: Option<&RangeListIndex<'a, Order>>
	) -> Result<Self, Error> {
		let info = sections.info;

		let compilation_units = {
			let mut vec = Vec::new();
			let mut cursor = Cursor::new(info);

			while let Some(compilation_unit) =
				TaggedRef::try_next_from_cursor::<Order>(&mut cursor)? {

				vec.push(compilation_unit);
			}

			vec
		};

		let index = compilation_units
			.into_par_iter()
			.map(|(name, compilation_unit_ref)| Ok((name, CompilationUnit::new(
				abbreviation,
				strings,
				str_offsets,
				addr,
				rnglists,
				compilation_unit_ref
			)?)))
			.collect::<Result<HashMap<_, _, _>, _>>()?;

		Ok(Self {
			index,
		})
	}

	pub fn get(&self, name: usize) -> Option<&CompilationUnit<'a, Order>> {
		self.index.get(&name)
	}

	pub fn par_iter<'b>(
		&'b self
	) -> impl ParallelIterator<Item = (&'b usize, &'b CompilationUnit<'a, Order>)> + 'b {
		self.index.par_iter()
	}

	pub fn iter<'b>(
		&'b self
	) -> impl Iterator<Item = (&'b usize, &'b CompilationUnit<'a, Order>)> + 'b {
		self.index.iter()
	}
}