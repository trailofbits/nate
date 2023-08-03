/* DWARF has a bunch of these, so no point in having Rust warn us of them. */
#![allow(non_upper_case_globals)]

/* We're using thiserror's #[backtrace] attribute. */
#![feature(provide_any)]
#![feature(error_generic_member_access)]

use anyhow::anyhow;
use byteorder::ByteOrder;
use dw5_consts::*;
use crate::abbreviation::AbbreviationIndex;
use crate::address::{AddressIndex, Range, RangeListIndex, RangesIndex};
use crate::cu::CompilationUnitIndex;
use crate::name::NameIndex;
use crate::str::{StringOffsetsIndex, StringsIndex};

mod leb;
mod abbreviation;
mod types;
mod name;
mod str;
mod die;
mod cu;
mod address;

pub use byteorder;
pub use die::{CompilationUnit, Die, AttributeValue};
pub use types::*;

pub struct Dwarf<'a, Order: ByteOrder> {
	_sections: DwarfSections<'a>,
	abbreviation: AbbreviationIndex<'a>,
	strings: StringsIndex<'a>,
	str_offsets: StringOffsetsIndex<'a, Order>,
	addr: Option<AddressIndex<'a, Order>>,
	ranges: Option<RangesIndex<'a, Order>>,
	rnglists: Option<RangeListIndex<'a, Order>>,
	compilation_units: CompilationUnitIndex<'a, Order>,
	names: NameIndex<'a, Order>,
}
impl<'a, Order> Dwarf<'a, Order>
	where Order: ByteOrder + Send + Sync + 'static {

	pub fn new(
		sections: DwarfSections<'a>
	) -> Result<Self, Error> {
		let timer = std::time::Instant::now();
		let abbreviation = AbbreviationIndex::new(&sections)?;
		tracing::info!("built abbreviation index in {:?}", timer.elapsed());

		let timer = std::time::Instant::now();
		let str_offsets = StringOffsetsIndex::new(&sections)?;
		tracing::info!("built string offset index in {:?}", timer.elapsed());

		let timer = std::time::Instant::now();
		let strings = StringsIndex::new(&sections)?;
		tracing::info!("built string index in {:?}", timer.elapsed());

		let timer = std::time::Instant::now();
		let addr = if sections.addr.is_some() {
			Some(AddressIndex::new(&sections)?)
		} else { None };
		tracing::info!("built address index in {:?}? {}", timer.elapsed(), addr.is_some());

		let timer = std::time::Instant::now();
		let ranges = if sections.ranges.is_some() {
			Some(RangesIndex::new(&sections)?)
		} else { None };
		tracing::info!("built ranges index in {:?}? {}", timer.elapsed(), ranges.is_some());

		let timer = std::time::Instant::now();
		let rnglists = if sections.rnglists.is_some() {
			Some(RangeListIndex::new(&sections)?)
		} else { None };
		tracing::info!("built range lists index in {:?}? {}", timer.elapsed(), ranges.is_some());

		let timer = std::time::Instant::now();
		let compilation_units = CompilationUnitIndex::new(
			&sections,
			&abbreviation,
			&strings,
			&str_offsets,
			addr.as_ref(),
			rnglists.as_ref()
		)?;
		tracing::info!("built compilation unit index in {:?}", timer.elapsed());

		let timer = std::time::Instant::now();
		let names = NameIndex::new(
			&abbreviation,
			&str_offsets,
			&strings,
			&compilation_units
		)?;
		tracing::info!("built name index in {:?}", timer.elapsed());

		Ok(Self {
			_sections: sections,
			abbreviation,
			strings,
			str_offsets,
			compilation_units,
			addr,
			ranges,
			rnglists,
			names,
		})
	}

	/// Finds a compilation unit by its offset from the start of the .debug_info
	/// section.
	pub fn find_cu_by_offset(&self, name: usize) -> Option<&CompilationUnit<'a, Order>> {
		self.compilation_units.get(name)
	}

	pub fn compilation_units<'b>(&'b self) -> impl Iterator<Item = (&'b usize, &'b CompilationUnit<'a, Order>)> {
		self.compilation_units.iter()
	}

	/// Get and resolve the attribute with a given name in a given DIE.
	fn get_die_attribute(&self,
		die: &Die<'a, Order>,
		name: AttributeName
	) -> Result<Option<AttributeValue<'a, Order>>, Error> {
		for attribute in die.attributes(&self.abbreviation)? {
			let attribute = attribute?;
			if attribute.name() == name {
				return Ok(Some(attribute.resolve(
					&self.strings,
					&self.str_offsets,
					self.addr.as_ref(),
					self.rnglists.as_ref(),
				)?))
			}
		}
		Ok(None)
	}

	/// Calculate the address range for a given compilation unit.
	pub fn get_cu_address_range(&self, cu: &CompilationUnit<'a, Order>) -> Result<Option<Range>, Error> {
		let root = cu.root()?;

		/* The operation we use to reduce iterators of ranges. */
		let range_reduce = |a: Result<Range, Error>, b: Result<Range, Error>| {
			let a = a?;
			let b = b?;

			Ok(Range {
				low: a.low.min(b.low),
				high: b.high.max(b.high),
			})
		};

		/* Gather the attributes we need. */
		let low_pc = self.get_die_attribute(&root, DW_AT_low_pc)?;
		let high_pc = self.get_die_attribute(&root, DW_AT_high_pc)?;
		let ranges = self.get_die_attribute(&root, DW_AT_ranges)?;

		let conditions = (
			low_pc,
			high_pc,
			ranges,
			cu.version(),
			cu.addr_base(),
			self.addr.as_ref(),
			self.ranges.as_ref(),
			self.rnglists.as_ref()
		);

		match conditions {
			/* The trivial case. One contiguous range from low_pc to high_pc. */
			(
				Some(AttributeValue::Address(low_pc)),
				Some(AttributeValue::Address(high_pc)),
				None,
				_,
				_,
				_,
				_,
				_
			) =>
				Ok(Some(Range { low: low_pc, high: high_pc })),
			/* Another trivial case. This compilation unit has no addresses. */
			(
				None,
				None,
				None,
				_,
				_,
				_,
				_,
				_
			) =>
				Ok(None),
			/* Non-contiguous ranges, DW_FORM_rnglistx. */
			(
				low_pc @ (Some(AttributeValue::Address(_)) | None),
				None,
				Some(AttributeValue::RangeList(range_list)),
				_,
				Some(addr_base),
				Some(addr),
				_,
				_
			) => {
				let low_pc = low_pc
					.map(|value| match value {
						AttributeValue::Address(low_pc) => low_pc,
						_ => unreachable!()
					});

				tracing::trace!("DW_AT_low_pc [DW_FORM_addr]: {:?}", low_pc);
				tracing::trace!("DW_AT_ranges [DW_FORM_rnglistx]:");

				range_list.ranges(addr_base, addr, low_pc)
					.inspect(|range| match range {
						Ok(range) => tracing::trace!("    [0x{:016x}, 0x{:016x})", range.low, range.high),
						Err(what) => tracing::trace!("    ! Error: {}", what)
					})
					.reduce(range_reduce)
					.transpose()
			},
			/* Non-contiguous ranges, DW_FORM_sec_offset, DWARF version 5. */
			(
				low_pc @ (Some(AttributeValue::Address(_)) | None),
				None,
				Some(AttributeValue::SectionOffset(name)),
				5,
				Some(addr_base),
				Some(addr),
				_,
				Some(rnglists)
			) => {
				let low_pc = low_pc
					.map(|value| match value {
						AttributeValue::Address(low_pc) => low_pc,
						_ => unreachable!()
					});

				let range_list = match rnglists.address(name) {
					Some(range_list) => range_list,
					None => return Err(Error::InvalidInfoSection {
						source: anyhow!("0x{:016x} does not name a valid range \
							list in the .debug_rnglists section",
							name),
					})
				};

				range_list.ranges(addr_base, addr, low_pc)
					.reduce(range_reduce)
					.transpose()
			},
			/* Non-contiguous ranges based at low_pc, DW_FORM_sec_offset,
			 * DWARF version 4. */
			(
				Some(AttributeValue::Address(low_pc)),
				None,
				Some(AttributeValue::SectionOffset(name)),
				4,
				_,
				_,
				Some(ranges),
				_
			) => {
				let ranges = match ranges.get(name, low_pc) {
					Some(ranges) => ranges,
					None => return Err(Error::InvalidInfoSection {
						source: anyhow!("0x{:016x} does not name a valid range \
							list in the .debug_ranges section",
							name),
					})
				};

				ranges.reduce(range_reduce).transpose()
			},
			configuration => return Err(Error::UnsupportedOperation {
				source: anyhow!("get_cu_address_range(): configuration {:?} is \
					not supported",
					configuration),
			})
		}
	}
}

/// DWARF environment information.
pub struct DwarfSections<'a> {
	/// The size of an address value in the target architecture, in bytes.
	pub address_size: u8,
	/// The .debug_info section.
	pub info: &'a [u8],
	/// The .debug_abbrev section.
	pub abbrev: &'a [u8],
	/// The .debug_str section.
	pub str: &'a [u8],
	/// The .debug_str_offsets section.
	pub str_offsets: &'a [u8],
	/// The .debug_addr section.
	///
	/// May not be present if all CUs are DWARF 4.
	pub addr: Option<&'a [u8]>,
	/// The .debug_ranges section.
	///
	/// May not be present if all CUs are DWARF 5.
	pub ranges: Option<&'a [u8]>,
	/// The .debug_rnglists section.
	///
	/// May not be present if all CUs are DWARF 4.
	pub rnglists: Option<&'a [u8]>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("invalid .debug_abbrev section: {source}")]
	InvalidAbbreviationSection {
		#[backtrace]
		source: anyhow::Error
	},
	#[error("invalid .debug_info section: {source}")]
	InvalidInfoSection {
		#[backtrace]
		source: anyhow::Error
	},
	#[error("invalid .debug_str_offsets section: {source}")]
	InvalidStringOffsetsSection {
		#[backtrace]
		source: anyhow::Error
	},
	#[error("invalid .debug_str section: {source}")]
	InvalidStringsSection {
		#[backtrace]
		source: anyhow::Error
	},
	#[error("invalid .debug_rnglists section: {source}")]
	InvalidRangeListsSection {
		#[backtrace]
		source: anyhow::Error
	},
	#[error("invalid .debug_ranges section: {source}")]
	InvalidRangesSection {
		#[backtrace]
		source: anyhow::Error
	},
	#[error("tried to perform an operation not supported by the library")]
	UnsupportedOperation {
		#[backtrace]
		source: anyhow::Error
	}
}
