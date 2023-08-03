use std::collections::HashMap;
use std::ffi::CStr;
use anyhow::anyhow;
use crate::Error;
use crate::abbreviation::AbbreviationIndex;
use crate::die::{AttributeValue, CompilationUnit};
use crate::str::{StringOffsetsIndex, StringsIndex};
use crate::cu::CompilationUnitIndex;
use byteorder::{ByteOrder};
use cstr::cstr;
use rayon::iter::ParallelIterator;
use smallvec::SmallVec;
use dw5_consts::*;

pub struct NameIndex<'a, Order: ByteOrder> {
	names: Vec<NameTree<'a>>,
	_bind0: std::marker::PhantomData<Order>,
}
impl<'a, Order> NameIndex<'a, Order>
	where Order: ByteOrder + Send + Sync + 'static {

	pub fn new(
		abbreviation: &AbbreviationIndex<'a>,
		str_offsets: &StringOffsetsIndex<'a, Order>,
		strings: &StringsIndex<'a>,
		compilation_units: &CompilationUnitIndex<'a, Order>
	) -> Result<Self, Error> {
		/* Parse the compilation units into a collection of name trees. */
		let names = compilation_units
			.par_iter()
			.map(|(name, compilation_unit)| {
				parse_compilation_unit::<Order>(
					abbreviation,
					strings,
					str_offsets,
					compilation_unit,
					*name
				)
			}).collect::<Result<Vec<_>, Error>>()?;

		Ok(Self {
			names,
			_bind0: Default::default()
		})
	}
}

macro_rules! resolve_at_name {
	($child:expr, $abbreviation:expr, $strings:expr, $str_offsets:expr) => {{
		let mut name = None;
		for attribute in $child.attributes($abbreviation)? {
			let attribute = attribute?;
			if attribute.name() == DW_AT_name {
				let val = attribute.resolve(
					$strings,
					$str_offsets,
					None,
					None)?;
				match val {
					AttributeValue::String(val) => name = Some(val),
					val => return Err(Error::InvalidInfoSection {
						source: anyhow!("value of DW_AT_name is not a \
							string: {:?}",
							val),
					})
				}
			}
		}
		name
	}}
}

/// Parse a compilation unit and produce a tree of symbol names from it.
fn parse_compilation_unit<'a, Order>(
	abbreviation: &AbbreviationIndex<'a>,
	strings: &StringsIndex<'a>,
	str_offsets: &StringOffsetsIndex<'a, Order>,
	compilation_unit: &CompilationUnit<'a, Order>,
	compilation_unit_name: usize,
) -> Result<NameTree<'a>, Error>
	where Order: ByteOrder + 'static {

	let root = compilation_unit.root()?;

	/* Since we're not doing this recursively, we stack up namespaces as we go
	 * deeper into the CU, and merge back down into their parent namespaces as
	 * we go back up. We save how the namespace should be called in its parent
	 * as well as what depth NULL DIE will close its scope.
	 *
	 * We have this set up so that the bottommost element is the root namespace
	 * of this CU, and return it when we're done. */
	let mut namespace_stack = SmallVec::<[(&'a CStr, u64, Namespace<'a>); 8]>::new();
	namespace_stack.push((cstr!(""), 0, Default::default()));

	/* Merges the given name node into the namespace at the top of the stack. */
	macro_rules! merge_top {
		($name:expr, $node:expr) => {{
			let node = $node;
			let current = &mut namespace_stack.last_mut().unwrap().2;
			if let Some(target) = current.get_mut($name) {
				target.merge(node);
			} else {
				current.insert($name, node);
			}
		}}
	}

	for child in root.descendants(abbreviation)? {
		let (depth, child) = child?;

		/* Handle NULL DIEs.
		 *
		 * Because we only care about one aspect of the hierarchy - namely:
		 * DW_TAG_namespace entries - we have to be careful in how we process
		 * these. We have to make sure we only ever closing a namespace if the
		 * NULL DIE is at the correct depth, ignoring it otherwise.
		 */
		if child.is_null() {
			let correct_depth = namespace_stack
				.last()
				.map(|(_, closing_depth, _)| {
					*closing_depth == depth
				})
				.unwrap_or(true);
			if !correct_depth || depth == 0 { continue }

			/* Pop the last element in the stack and prepare to merge it into
			 * the new top of the stack. */
			let element = namespace_stack.pop()
				.and_then(|(name, _, namespace)| Some((
					name,
					namespace,
					namespace_stack.last_mut()?
				)));

			/* Because of how descendant iteration works, if it is ever the case
			 * that either element can't be found, we did something wrong and
			 * this is a bug. */
			let (name, namespace, (_, _, current)) = element.unwrap();

			/* Merge this namespace into the node with this name if it is not
			 * empty. */
			if !namespace.is_empty() {
				merge_top!(name, NameTreeNode {
					function: None,
					ty: None,
					namespace: Some(namespace),
				});

			}

			/* Move on to the next descendant, we've done all we can. */
			continue
		}

		/* Move on to handling specific abbreviations. */
		let child_abbrev = child.abbreviation(abbreviation)?;
		if child_abbrev.tag() == DW_TAG_subprogram {
			if let Some(name) = resolve_at_name!(child, abbreviation, strings, str_offsets) {
				merge_top!(name, NameTreeNode {
					function: Some(compilation_unit_name),
					ty: None,
					namespace: None,
				});
			}
		} else if child_abbrev.tag() == DW_TAG_base_type
			|| child_abbrev.tag() == DW_TAG_typedef
			|| child_abbrev.tag() == DW_TAG_array_type
			|| child_abbrev.tag() == DW_TAG_structure_type
			|| child_abbrev.tag() == DW_TAG_class_type
			|| child_abbrev.tag() == DW_TAG_enumeration_type
			|| child_abbrev.tag() == DW_TAG_union_type
			|| child_abbrev.tag() == DW_TAG_atomic_type
			|| child_abbrev.tag() == DW_TAG_coarray_type
			|| child_abbrev.tag() == DW_TAG_const_type
			|| child_abbrev.tag() == DW_TAG_dynamic_type
			|| child_abbrev.tag() == DW_TAG_file_type
			|| child_abbrev.tag() == DW_TAG_pointer_type
			|| child_abbrev.tag() == DW_TAG_immutable_type
			|| child_abbrev.tag() == DW_TAG_interface_type
			|| child_abbrev.tag() == DW_TAG_packed_type
			|| child_abbrev.tag() == DW_TAG_reference_type
			|| child_abbrev.tag() == DW_TAG_restrict_type
			|| child_abbrev.tag() == DW_TAG_string_type
			|| child_abbrev.tag() == DW_TAG_set_type
			|| child_abbrev.tag() == DW_TAG_subrange_type
			|| child_abbrev.tag() == DW_TAG_subroutine_type
			|| child_abbrev.tag() == DW_TAG_thrown_type
			|| child_abbrev.tag() == DW_TAG_volatile_type
			|| child_abbrev.tag() == DW_TAG_unspecified_type  {

			if let Some(name) = resolve_at_name!(child, abbreviation, strings, str_offsets) {
				merge_top!(name, NameTreeNode {
					function: None,
					ty: Some(compilation_unit_name),
					namespace: None,
				});
			}
		}

		/* Since we cull empty namespaces out anyway, don't even bother if a
		 * namespace has no children. This also gives us the added bonus of not
		 * having to handle the "the namespace DIE didn't actually have any
		 * children, hahaha" edge case in the NULL die part of this loop, which
		 * is nice. */
		if child_abbrev.tag() == DW_TAG_namespace && child_abbrev.has_children() {
			let name = resolve_at_name!(child, abbreviation, strings, str_offsets)
				.unwrap_or(cstr!("<anonymous>"));
			namespace_stack.push((name, depth + 1, Default::default()));
		}
	}

	/* Having any more namespaces in the stack at this point means we didn't
	 * parse all of the NULL dies correctly, and there's a bug somewhere. Stop
	 * early so we don't spit out nonsense. */
	assert_eq!(namespace_stack.len(), 1);

	Ok(NameTree {
		root: namespace_stack.pop().unwrap().2,
	})
}

/// The type representing the namespace.
type Namespace<'a> = HashMap<&'a CStr, NameTreeNode<'a>, ahash::RandomState>;

/// A name node.
///
/// Name nodes contain information pertaining to a given name in the name tree.
#[derive(Debug)]
struct NameTreeNode<'a> {
	/// The name of the CU containing a function with this name, if any.
	function: Option<usize>,
	/// The name of the CU containing a type with this name, if any.
	ty: Option<usize>,
	/// The name of the CU containing a
	/// The subtree this name is mapped to, if any.
	namespace: Option<Namespace<'a>>,
}
impl<'a> NameTreeNode<'a> {
	/// Merges the subtree originating at a given node into this node.
	pub fn merge(&mut self, other: Self) -> Option<()> {
		match (&mut self.function, other.function) {
			(Some(_), Some(_)) =>
				/* Can't merge, bail!
				 * TODO: Stop doing this the funny way. */
				{},
			(a, b) if a.is_none() =>
				*a = b,
			_ => {},
		}

		match (&mut self.ty, other.ty) {
			(Some(_), Some(_)) =>
			/* Can't merge, bail!
			 * TODO: Stop doing this the funny way. */
				{},
			(a, b) if a.is_none() =>
				*a = b,
			_ => {},
		}

		match (&mut self.namespace, other.namespace) {
			(Some(a), Some(b)) =>
				merge_namespace(a, b)?,
			(a, b) if a.is_none() =>
				*a = b,
			_ => {}
		}
		Some(())
	}
}

/// Handles recursive merging of two namespaces.
fn merge_namespace<'a>(a: &mut Namespace<'a>, mut b: Namespace<'a>) -> Option<()> {
	/* Merge all overlapping values. */
	for (key, value) in a.iter_mut() {
		let a = value;
		let b = match b.remove(key) {
			Some(b) => b,
			None => continue
		};

		a.merge(b)?;
	}

	/* We know there are no overlapping names in B at this point, so just
	 * move everything from B to A. */
	a.extend(b.into_iter());

	Some(())
}

#[derive(Debug)]
struct NameTree<'a> {
	root: Namespace<'a>
}
impl<'a> NameTree<'a> {
	pub fn new() -> Self {
		Self {
			root: Default::default(),
		}
	}

	pub fn merge(&mut self, other: NameTree<'a>) -> Option<()> {
		let a = &mut self.root;
		let b = other.root;

		merge_namespace(a, b)
	}
}
