use std::ffi::c_int;
use std::ptr::NonNull;
use nate::byteorder::{BigEndian, LittleEndian};
use nate::{Address, CompilationUnit, Dwarf, DwarfSections};

/// The
#[repr(i8)]
pub enum NateStatus {
	Success = 0,
	InvalidEndianness = -1,
	DwarfInstanceIsNull = -2,
	CompilationUnitInstanceIsNull = -7,
	RequiredSectionIsNull = -3,
	EndiannessMismatch = -4,
	InternalError = -5,
	NotFound = -6
}

#[repr(u8)]
pub enum NateEndianness {
	Little,
	Big,
}

pub struct NateDwarf<'a> {
	decoder: DynamicDwarf<'a>
}

pub struct NateCompilationUnit<'a> {
	comp_unit: DynamicCompilationUnit<'a>
}

enum DynamicCompilationUnit<'a> {
	LittleEndian(CompilationUnit<'a, LittleEndian>),
	BigEndian(CompilationUnit<'a, BigEndian>),
}

enum DynamicDwarf<'a> {
	LittleEndian(Dwarf<'a, LittleEndian>),
	BigEndian(Dwarf<'a, BigEndian>),
}

macro_rules! require_ok {
	($expr:expr) => {{
		match $expr {
			Ok(value) => value,
			Err(what) => {
				tracing::error!("{}(): {}, at {}:{}",
					function_name!(),
					what,
					std::file!(),
					std::line!());
				return Err(NateStatus::InternalError)
			}
		}
	}}
}

macro_rules! set_if_not_null {
	($ptr:expr, $value:expr) => {{
		if let Some(ptr) = $ptr {
			*ptr.as_ptr() = $value;
		}
	}}
}

macro_rules! run_in_unwindable_context {
	($closure:expr) => {{
		let result = std::panic::catch_unwind($closure);
		match result {
			Ok(result) => result,
			Err(panic) => {
				let report = |panic: Option<&str>| std::panic::catch_unwind(|| {
					tracing::error!("[libnate_c] {}() panicked: {}",
						function_name!(),
						match panic {
							Some(panic) => panic,
							None => "<unknown>"
						},);
				});

				let report = if let Some(string) = panic.downcast_ref::<String>() {
					report(Some(&string))
				} else if let Some(string) = panic.downcast_ref::<&str>() {
					report(Some(string))
				} else {
					report(None)
				};

				if let Err(_) = report {
					eprintln!("[libnate_c] {}(): Could not use tracing to \
						report panic. Something is seriously wrong! at {}:{}",
						function_name!(),
						std::file!(),
						std::line!())
				}

				return NateStatus::InternalError
			}
		}
	}}
}

#[no_mangle]
#[function_name::named]
pub unsafe extern "C" fn nate_dwarf_find_cu_by_offset(
	dwarf: Option<&'static NateDwarf<'static>>,
	offset: usize,
	compilation_unit: Option<NonNull<*mut NateCompilationUnit<'static>>>,
) -> NateStatus {
	let dwarf = match dwarf {
		Some(dwarf) => dwarf,
		None => return NateStatus::DwarfInstanceIsNull,
	};

	let result = run_in_unwindable_context!(|| {
		let comp_unit = match &dwarf.decoder {
			DynamicDwarf::LittleEndian(decoder) =>
				decoder.find_cu_by_offset(offset)
					.cloned()
					.map(|cu| DynamicCompilationUnit::LittleEndian(cu)),
			DynamicDwarf::BigEndian(decoder) =>
				decoder.find_cu_by_offset(offset)
					.cloned()
					.map(|cu| DynamicCompilationUnit::BigEndian(cu))
		};
		comp_unit.map(|comp_unit| Box::into_raw(Box::new(NateCompilationUnit {
			comp_unit
		})))
	});

	match result {
		Some(result) => {
			set_if_not_null!(compilation_unit, result);
			NateStatus::Success
		},
		None => NateStatus::NotFound
	}
}

#[no_mangle]
#[function_name::named]
pub unsafe extern "C" fn nate_cu_range(
	dwarf: Option<&'static NateDwarf<'static>>,
	compilation_unit: Option<&'static NateCompilationUnit<'static>>,
	has_range: Option<NonNull<c_int>>,
	low_pc: Option<NonNull<Address>>,
	high_pc: Option<NonNull<Address>>,
) -> NateStatus {
	let (dwarf, compilation_unit) = match (dwarf, compilation_unit){
		(Some(dwarf), Some(compilation_unit)) =>
			(dwarf, compilation_unit),
		(None, _) =>
			return NateStatus::DwarfInstanceIsNull,
		(_, None) =>
			return NateStatus::CompilationUnitInstanceIsNull
	};

	let range = run_in_unwindable_context!(|| match (&dwarf.decoder, &compilation_unit.comp_unit) {
		(
			DynamicDwarf::BigEndian(decoder),
			DynamicCompilationUnit::BigEndian(comp_unit)
		) =>
			Ok(require_ok!(decoder.get_cu_address_range(comp_unit))),
		(
			DynamicDwarf::LittleEndian(decoder),
			DynamicCompilationUnit::LittleEndian(comp_unit)
		) =>
			Ok(require_ok!(decoder.get_cu_address_range(comp_unit))),
		_ =>
			return Err(NateStatus::EndiannessMismatch)
	});

	match range {
		Ok(Some(range)) => {
			set_if_not_null!(has_range, 1);
			set_if_not_null!(low_pc, range.low);
			set_if_not_null!(high_pc, range.high);
		},
		Ok(None) =>
			set_if_not_null!(has_range, 0),
		Err(what) =>
			return what
	};

	NateStatus::Success
}


#[no_mangle]
#[function_name::named]
pub unsafe extern "C" fn nate_cu_free(
	dwarf: Option<&'static NateDwarf<'static>>,
	compilation_unit: Option<NonNull<*mut NateCompilationUnit<'static>>>,
) -> NateStatus {
	/* We don't actually use the context instance here, but it's a good idea to
	 * give us flexibility in knowing that, if we ever actually need to use it,
	 * we won't need to change the signature of this function. */
	let _dwarf = match dwarf {
		Some(dwarf) => dwarf,
		None => return NateStatus::DwarfInstanceIsNull,
	};

	if let Some(compilation_unit) = compilation_unit {
		let compilation_unit = compilation_unit.as_ptr();

		/* Just trust the consumer will do the right thing here, rebuild the box
		 * we gave them and let Rust free the structure. */
		run_in_unwindable_context!(|| { let _ = Box::from_raw(*compilation_unit); });

		*compilation_unit = std::ptr::null_mut();
	}

	NateStatus::Success
}

#[no_mangle]
#[function_name::named]
pub unsafe extern "C" fn nate_dwarf_new(
	target: Option<NonNull<*mut NateDwarf<'static>>>,
	endian: u8,
	address_size: u8,
	info: Option<NonNull<u8>>,
	info_len: usize,
	abbrev: Option<NonNull<u8>>,
	abbrev_len: usize,
	str: Option<NonNull<u8>>,
	str_len: usize,
	str_offsets: Option<NonNull<u8>>,
	str_offsets_len: usize,
	addr: Option<NonNull<u8>>,
	addr_len: usize,
	ranges: Option<NonNull<u8>>,
	ranges_len: usize,
	rnglists: Option<NonNull<u8>>,
	rnglists_len: usize,
) -> NateStatus {
	let endian = if endian == NateEndianness::Little as u8 {
		NateEndianness::Little
	} else if endian == NateEndianness::Big as u8 {
		NateEndianness::Big
	} else {
		return NateStatus::InvalidEndianness
	};
	let target = match target {
		Some(target) => target,
		None => return NateStatus::Success
	};

	macro_rules! require_section {
		($ptr:expr, $len:expr) => {{
			match map_slice($ptr, $len) {
				Some(section) => section,
				None =>
					return NateStatus::RequiredSectionIsNull
			}
		}}
	}

	let sections = DwarfSections::<'static> {
		address_size,
		info: require_section!(info, info_len),
		abbrev: require_section!(abbrev, abbrev_len),
		str: require_section!(str, str_len),
		str_offsets: require_section!(str_offsets, str_offsets_len),
		addr: map_slice(addr, addr_len),
		ranges: map_slice(ranges, ranges_len),
		rnglists: map_slice(rnglists, rnglists_len),
	};

	let result = run_in_unwindable_context!(|| {
		let decoder = match endian {
			NateEndianness::Little =>
				DynamicDwarf::LittleEndian(require_ok!(Dwarf::new(sections))),
			NateEndianness::Big =>
				DynamicDwarf::BigEndian(require_ok!(Dwarf::new(sections))),
		};
		let dwarf = NateDwarf {
			decoder,
		};

		Ok(Box::into_raw(Box::new(dwarf)))
	});

	let result = match result {
		Ok(value) => value,
		Err(what) => return what,
	};
	*target.as_ptr() = result;

	NateStatus::Success
}

unsafe fn map_slice<'a>(ptr: Option<NonNull<u8>>, len: usize) -> Option<&'a [u8]> {
	ptr.map(|ptr| std::slice::from_raw_parts(ptr.as_ptr(), len))
}

#[no_mangle]
#[function_name::named]
pub unsafe extern "C" fn nate_dwarf_free(
	target: Option<NonNull<*mut NateDwarf<'static>>>
) -> NateStatus {
	if let Some(target) = target {
		let target = target.as_ptr();

		/* Just trust the consumer will do the right thing here, rebuild the box
		 * we gave them and let Rust free the structure. */
		run_in_unwindable_context!(|| { let _ = Box::from_raw(*target); });

		*target = std::ptr::null_mut();
	}

	NateStatus::Success
}
