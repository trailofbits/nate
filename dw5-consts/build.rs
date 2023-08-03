use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use serde_yaml::Value;

fn main() {
	println!("cargo:rerun-if-changed=dwarf-consts/dwarf5.yml");

	let consts = File::open("dwarf-consts/dwarf5.yml").unwrap();
	let data: Vec<Value> = serde_yaml::from_reader(consts).unwrap();

	let add_u8 = &add_u8 as &TypedAddFn;
	let add_u16 = &add_u16 as &TypedAddFn;

	let mut map = HashMap::new();
	map.insert("Table 7.2 Unit Header Types", add_u8);
	map.insert("Table 7.3: Tag encodings", add_u16);
	map.insert("Table 7.4: Child determination encodings", add_u8);
	map.insert("Table 7.5: Attribute encodings", add_u16);
	map.insert("Table 7.6: Attribute form encodings", add_u8);
	map.insert("Table 7.9: DWARF operation encodings", add_u8);
	map.insert("Table 7.10: Location list entry encoding values", add_u8);
	map.insert("Table 7.11: Base type encoding values", add_u8);
	map.insert("Table 7.12: Decimal sign encodings", add_u8);
	map.insert("Table 7.13: Endianity encodings", add_u8);
	map.insert("Table 7.14: Accessibility encodings", add_u8);
	map.insert("Table 7.15: Visibility encodings", add_u8);
	map.insert("Table 7.16: Virtuality encodings", add_u8);
	map.insert("Table 7.17: Language encodings", add_u16);
	map.insert("Table 7.18: Identifier case encodings", add_u8);
	map.insert("Table 7.19: Calling convention encodings", add_u8);
	map.insert("Table 7.20: Inline encodings", add_u8);
	map.insert("Table 7.21: Ordering encodings", add_u8);
	map.insert("Table 7.22: Discriminant descriptor encodings", add_u8);
	map.insert("Table 7.23: Name index attribute encodings", add_u16);
	map.insert("Table 7.24: Defaulted attribute encodings", add_u8);
	map.insert("Table 7.25: Line number standard opcode encodings", add_u8);
	map.insert("Table 7.26: Line number extended opcode encodings", add_u8);
	map.insert("Table 7.27: Line number header entry format encodings", add_u16);
	map.insert("Table 7.28: Macro information entry type encodings", add_u8);
	map.insert("Table 7.30: Range list entry encoding values", add_u8);


	let mut out_dir = std::env::var_os("OUT_DIR").unwrap();
	out_dir.push("/consts.rs");

	let mut target = File::create(out_dir).unwrap();
	for value in data {
		let value = value.as_mapping().unwrap();
		let name = value.get("name").unwrap().as_str().unwrap();
		let mapper = match map.get(name) {
			Some(mapper) => mapper,
			None => {
				eprintln!("unknown table name: {}", name);
				continue
			}
		};
		let body = value.get("body").unwrap().as_sequence().unwrap();
		for item in body {
			let item = item.as_sequence().unwrap();
			let name = item.get(0).unwrap().as_str().unwrap();
			let value = item.get(1).unwrap().as_u64().unwrap();
			if name == "Reserved" { continue }
			(mapper)(&mut target, name, value).unwrap();
		}
	}
}

type TypedAddFn = dyn Fn(&mut dyn Write, &str, u64) -> std::io::Result<()>;

fn add_u8(file: &mut dyn Write, name: &str, value: u64) -> std::io::Result<()> {
	writeln!(file, "pub const {}: u8 = 0x{:x};", name, value)
}

fn add_u16(file: &mut dyn Write, name: &str, value: u64) -> std::io::Result<()> {
	writeln!(file, "pub const {}: u16 = 0x{:x};", name, value)
}
