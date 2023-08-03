#![feature(seek_stream_len)]
#![feature(error_generic_member_access)]

use std::fs::File;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use elf::ElfBytes;
use elf::endian::AnyEndian;
use elf::file::Class;
use nate::{Dwarf, DwarfSections};

macro_rules! section {
	($elf:expr, $name:expr) => {{
		if let Some(name) = &$elf.section_header_by_name($name)? {
			let (a, b) = $elf.section_data(name)?;
			if b.is_some() {
				panic!("no support for compressed sections!")
			}

			Some(a)
		} else { None }
	}}
}

fn main() -> anyhow::Result<()> {
	tracing_subscriber::fmt::init();

	let binary = {
		let mut args = std::env::args_os();
		let name = args.next().unwrap();
		let bin = match args.next() {
			Some(bin) => bin,
			None => {
				eprintln!("Usage: {:?} <binary.elf>", name);
				std::process::exit(1)
			}
		};
		bin
	};

	let binary = File::open(binary)?;
	let binary = unsafe {
		memmap2::MmapOptions::new()
			.map(&binary)
	}?;
	// let binary = std::fs::read(binary)?;
	let elf = ElfBytes::<AnyEndian>::minimal_parse(&binary[..])?;
	match elf.ehdr.endianness {
		AnyEndian::Big => process::<BigEndian>(&elf),
		AnyEndian::Little => process::<LittleEndian>(&elf)
	}
}

fn process<B>(elf: &ElfBytes<AnyEndian>) -> anyhow::Result<()>
	where B: ByteOrder + Send + Sync + 'static {

	let sections = DwarfSections {
		address_size: match elf.ehdr.class {
			Class::ELF32 => 4,
			Class::ELF64 => 8
		},
		info: section!(elf, ".debug_info").unwrap(),
		abbrev: section!(elf, ".debug_abbrev").unwrap(),
		str: section!(elf, ".debug_str").unwrap(),
		str_offsets: section!(elf, ".debug_str_offsets").unwrap(),
		addr: section!(elf, ".debug_addr"),
		rnglists: section!(elf, ".debug_rnglists"),
		ranges: section!(elf, ".debug_ranges"),
	};
	let dwarf = Dwarf::<B>::new(sections)?;

	// let mut cus = dwarf.compilation_units().collect::<Vec<_>>();
	// cus.sort_unstable_by_key(|(key, _)| **key);
	//
	// for (name, _) in cus {
	// 	println!("0x{:016x}", name);
	// }

	// let cu = dwarf.find_cu_by_offset(0x00c0d5a0).unwrap();
	// let range = dwarf.get_cu_address_range(cu)?.unwrap();
	//
	// println!("{:?}", range);

	loop {}

	Ok(())
}
