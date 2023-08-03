use std::collections::HashMap;
use anyhow::anyhow;
use dw5_consts::DW_FORM_implicit_const;
use crate::{DwarfSections, Error};
use crate::leb::{ULeb128, TargetIntegerTooNarrow};
use crate::types::{AttributeName, FormName, TagName};

pub struct Abbreviation {
	attributes: Vec<AbbreviationAttribute>,
	child: bool,
	tag: TagName,
	static_len: Option<usize>,
}
impl Abbreviation {
	pub fn tag(&self) -> TagName {
		self.tag
	}

	pub fn has_children(&self) -> bool {
		self.child
	}

	pub fn attributes(&self) -> std::slice::Iter<AbbreviationAttribute> {
		self.attributes.iter()
	}

	/// Static length of the attributes in a DIE with this abbreviation, if
	/// available.
	///
	/// # Static length
	/// DIEs belonging to some abbreviations can have their sizes known from
	/// just the information on the abbreviation itself, requiring no extra
	/// interpreting of the data in the DIE.
	///
	pub fn static_attributes_len(&self) -> Option<usize> {
		self.static_len
	}
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AbbreviationAttribute {
	pub name: AttributeName,
	pub form: FormName
}

pub type AbbreviationCode = u64;

/// Abbreviations are uniquely identified by the table they belong to as well as
/// a code number that distinguishes a given abbreviation from others in the same
/// table as it.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AbbreviationKey {
	pub table: usize,
	pub code: AbbreviationCode
}

pub struct AbbreviationIndex<'a> {
	index: HashMap<AbbreviationKey, Abbreviation, ahash::RandomState>,
	_bind: std::marker::PhantomData<&'a ()>,
}
impl<'a> AbbreviationIndex<'a> {
	pub fn new(sections: &DwarfSections<'a>) -> Result<Self, Error> {
		let mut index = HashMap::default();
		let data = sections.abbrev;

		macro_rules! read_uleb128 {
			($data:expr, $offset:expr) => {{
				let value = ULeb128::new($data, $offset)
					.map_err(|what| Error::InvalidAbbreviationSection {
						source: anyhow!(what)
					})?;
				$offset += value.len();

				value
			}}
		}

		let mut offset = 0usize;
		let mut table_offset = 0usize;
		loop {
			if offset >= data.len() {
				if offset == table_offset {
					/* We're done. */
					break
				} else {
					/* The table data isn't complete. */
					return Err(Error::InvalidAbbreviationSection {
						source: anyhow!("data ended in the middle of an \
							abbreviation table"),
					})
				}
			}

			/* Try to read the abbreviation code and return a special error if
			 * it does not fit. This error can be used later to retry the
			 * building of the index with a larger integer later. */
			let code: u64 = read_uleb128!(data, offset)
				.try_into()
				.map_err(|what: TargetIntegerTooNarrow| Error::InvalidAbbreviationSection {
					source: anyhow!(what)
				})?;

			/* Move on to the next table if the code is zero */
			if code == 0 {
				table_offset = offset;
				continue
			}

			/* Make sure the tag value isn't greater than DW_TAG_hi_user. */
			let tag: TagName = read_uleb128!(data, offset)
				.try_into()
				.map_err(|what: TargetIntegerTooNarrow| Error::InvalidAbbreviationSection {
					source: anyhow!(what)
				})?;

			/* Read and validate the child determination byte. */
			let child = *data.get(offset)
				.ok_or_else(|| Error::InvalidAbbreviationSection {
					source: anyhow!("eof before child determination byte")
				})?;
			let child = match child {
				0 => false,
				1 => true,
				v => return Err(Error::InvalidAbbreviationSection {
					source: anyhow!("section has invalid child determination \
						byte value {} at offset {}", v, offset)
				})
			};
			offset += 1;

			/* Scan through the attributes until we find the end of this
			 * entry. */
			let mut static_len = Some(0usize);
			let mut abbreviation_attributes = Vec::new();
			loop {
				let a = read_uleb128!(data, offset);
				let b = read_uleb128!(data, offset);
				if a.is_zero() && b.is_zero() { break }

				/* Validate a and b so that we know they both fit inside a
				 * AttributeName and a FormName type, respectively. */
				let name: AttributeName = a.try_into()
					.map_err(|what| Error::InvalidAbbreviationSection {
						source: anyhow!("section has invalid attribute name \
						value at offset {}: {}", offset, what)
					})?;
				let form: FormName = b.try_into()
					.map_err(|what| Error::InvalidAbbreviationSection {
						source: anyhow!("section has invalid form name value \
						at offset {}: {}", offset, what)
					})?;

				abbreviation_attributes.push(AbbreviationAttribute {
					name,
					form,
				});

				/* Add the static size of this attribute, if any, to the
				 * accumulated static size of the attributes. */
				static_len = crate::die::static_form_len(form)
					.and_then(|a| static_len.map(|b| a + b));

				/* Handle the special case of DW_FORM_implicit_const, when the
				 * otherwise regular pattern of two ULEB128s per entry gets
				 * spiced up with with an extra fun™ third ULEB128 value that we
				 * can't forget to skip over or things go haywire down the line.
				 */
				if form == DW_FORM_implicit_const {
					read_uleb128!(data, offset);
				}
			}

			/* Finish this entry. */
			index.insert(
				AbbreviationKey {
					table: table_offset,
					code,
				},
				Abbreviation {
					attributes: abbreviation_attributes,
					child,
					tag,
					static_len,
				}
			);
		}

		Ok(Self { index, _bind: Default::default() })
	}

	pub fn get(&self, table: usize, code: u64) -> Option<&Abbreviation> {
		self.index.get(&AbbreviationKey { table, code })
	}

	pub fn len(&self) -> usize {
		self.index.len()
	}

	pub fn iter(&self)
		-> impl Iterator<Item = (&AbbreviationKey, &Abbreviation)> {

		self.index.iter()
	}
}