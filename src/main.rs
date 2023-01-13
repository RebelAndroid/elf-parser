use std::{
    alloc::System,
    collections::HashMap,
    env,
    ffi::{CStr, CString},
    fs::File,
    io::Read,
    process::ExitCode,
};

#[derive(Debug)]
struct EIdent {
    ei_mag: [u8; 4],
    ei_class: ELFClass,
    ei_data: ELFData,
    ei_version: u8,
    ei_os_abi: ELFABI,
    ei_abi_version: u8,
    ei_pad: [u8; 7],
}

#[derive(PartialEq, Debug)]
enum ELFClass {
    ClassNone,
    Class32,
    Class64,
}

#[derive(Debug)]
enum ELFData {
    ELFDataNone,
    ELFData2LSB,
    ELFDATA2MSB,
}

#[derive(Debug)]
enum ELFABI {
    None,
    Linux,
}

#[derive(Debug, Clone, Copy)]
enum ELFAddress {
    ELF64(u64),
    ELF32(u32),
}

#[derive(Debug)]
enum ELFType {
    None,
    Relocatable,
    Executable,
    SharedObject,
    Core,
    Other,
}

#[derive(Debug)]
enum ELFMachine {
    None,
    I386,
    AMD64,
    Other,
}

#[derive(Debug)]
struct ELFHeader {
    e_type: ELFType,
    machine: ELFMachine,
    version: u32,
    entry_point: ELFAddress,
    program_header_offset: ELFAddress,
    section_header_offset: ELFAddress,
    flags: u32,
    header_size: u16,
    program_header_entry_size: u16,
    program_header_entry_count: u16,
    section_header_entry_size: u16,
    section_header_entry_count: u16,
    section_header_string_table_index: u16,
}

#[derive(Debug, PartialEq)]
enum ELFSectionType {
    Null,
    ProgramBits,
    SymbolTable,
    StringTable,
    RelocationWithAddends,
    SymbolHashTable,
    Dynamic,
    Note,
    NoBits,
    Relocation,
    SHLIB,
    DynamicLinkingSymbolTable,
    InitArray,
    PreInitArray,
    FiniArray,
    Group,
    SYMTABSHNDX,
}

#[derive(Debug)]
struct ELFSectionHeader {
    name: u32,
    section_type: ELFSectionType,
    flags: ELFAddress,
    address: ELFAddress,
    offset: ELFAddress,
    size: ELFAddress,
    link: u32,
    info: u32,
    address_alignment: ELFAddress,
    entry_size: ELFAddress,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let file = File::open(&args[1]).unwrap();
    let file_bytes: Vec<u8> = file.bytes().map(|byte| byte.unwrap()).collect();

    let e_ident = parse_e_ident(&file_bytes);

    if e_ident.ei_pad != [0; 7] {
        println!(
            "unknown data in padding: {:#?}\nExpected: {:#?}",
            e_ident.ei_pad, [0; 7]
        );
    }
    println!("ELF identification information:\n{:#?}", e_ident);

    let (elf_header, next_byte) =
        parse_header(&file_bytes[16..], e_ident.ei_class, e_ident.ei_data);

    println!("ELF Header info:\n{:#?}", elf_header);

    let section_header_offset = match elf_header.section_header_offset {
        ELFAddress::ELF64(x) => x,
        ELFAddress::ELF32(x) => x as u64,
    };

    // index of the first byte after the end of the section header
    let section_header_end: u64 = match elf_header.section_header_offset {
        ELFAddress::ELF64(x) => x,
        ELFAddress::ELF32(x) => x as u64,
    } + elf_header.section_header_entry_count as u64
        * elf_header.section_header_entry_size as u64;

    if (file_bytes.len() as u64) < section_header_end {
        panic!("section header goes beyond end of file! Length of file: {}, expected end of header_file: {}", file_bytes.len(), section_header_end);
    }

    let (first_section_header, section_header_entry_count, section_header_string_table_index)
     = parse_first_section_header(&file_bytes[section_header_offset as usize..], elf_header, e_ident.ei_class, e_ident.ei_data);

    // then parse the rest
    let mut section_headers: Vec<ELFSectionHeader> = vec![first_section_header];
    for section_header_index in 1..section_header_entry_count {
        let index = match elf_header.section_header_offset {
            ELFAddress::ELF64(x) => x as usize,
            ELFAddress::ELF32(x) => x as usize,
        } + section_header_index as usize
            * elf_header.section_header_entry_size as usize;

        let var_index = match e_ident.ei_class {
            ELFClass::ClassNone => unreachable!(),
            ELFClass::Class32 => index + 24,
            ELFClass::Class64 => index + 40,
        };

        let section_header = ELFSectionHeader {
            name: u32_parse_bytes(file_bytes[index..index + 4].try_into().unwrap()),
            section_type: match u32_parse_bytes(
                file_bytes[index + 4..index + 8].try_into().unwrap(),
            ) {
                0 => ELFSectionType::Null,
                1 => ELFSectionType::ProgramBits,
                2 => ELFSectionType::SymbolTable,
                3 => ELFSectionType::StringTable,
                4 => ELFSectionType::RelocationWithAddends,
                5 => ELFSectionType::SymbolHashTable,
                6 => ELFSectionType::Dynamic,
                7 => ELFSectionType::Note,
                8 => ELFSectionType::NoBits,
                9 => ELFSectionType::Relocation,
                10 => ELFSectionType::SHLIB,
                11 => ELFSectionType::DynamicLinkingSymbolTable,
                14 => ELFSectionType::InitArray,
                15 => ELFSectionType::FiniArray,
                16 => ELFSectionType::PreInitArray,
                17 => ELFSectionType::Group,
                18 => ELFSectionType::SYMTABSHNDX,
                _ => ELFSectionType::Null, // TODO special section types
            },
            flags: match e_ident.ei_class {
                ELFClass::ClassNone => unreachable!(),
                ELFClass::Class32 => ELFAddress::ELF32(u32_parse_bytes(
                    file_bytes[index + 8..index + 12].try_into().unwrap(),
                )),
                ELFClass::Class64 => ELFAddress::ELF64(u64_parse_bytes(
                    file_bytes[index + 8..index + 16].try_into().unwrap(),
                )),
            },
            address: match e_ident.ei_class {
                ELFClass::ClassNone => unreachable!(),
                ELFClass::Class32 => ELFAddress::ELF32(u32_parse_bytes(
                    file_bytes[index + 12..index + 16].try_into().unwrap(),
                )),
                ELFClass::Class64 => ELFAddress::ELF64(u64_parse_bytes(
                    file_bytes[index + 16..index + 24].try_into().unwrap(),
                )),
            },
            offset: match e_ident.ei_class {
                ELFClass::ClassNone => unreachable!(),
                ELFClass::Class32 => ELFAddress::ELF32(u32_parse_bytes(
                    file_bytes[index + 16..index + 20].try_into().unwrap(),
                )),
                ELFClass::Class64 => ELFAddress::ELF64(u64_parse_bytes(
                    file_bytes[index + 24..index + 32].try_into().unwrap(),
                )),
            },
            size: match e_ident.ei_class {
                ELFClass::ClassNone => unreachable!(),
                ELFClass::Class32 => ELFAddress::ELF32(u32_parse_bytes(
                    file_bytes[index + 20..index + 24].try_into().unwrap(),
                )),
                ELFClass::Class64 => ELFAddress::ELF64(u64_parse_bytes(
                    file_bytes[index + 32..index + 40].try_into().unwrap(),
                )),
            },
            link: u32_parse_bytes(file_bytes[var_index..var_index + 4].try_into().unwrap()),
            info: u32_parse_bytes(file_bytes[var_index + 4..var_index + 8].try_into().unwrap()),
            address_alignment: match e_ident.ei_class {
                ELFClass::ClassNone => unreachable!(),
                ELFClass::Class32 => ELFAddress::ELF32(u32_parse_bytes(
                    file_bytes[var_index + 8..var_index + 12]
                        .try_into()
                        .unwrap(),
                )),
                ELFClass::Class64 => ELFAddress::ELF64(u64_parse_bytes(
                    file_bytes[var_index + 8..var_index + 16]
                        .try_into()
                        .unwrap(),
                )),
            },
            entry_size: match e_ident.ei_class {
                ELFClass::ClassNone => unreachable!(),
                ELFClass::Class32 => ELFAddress::ELF32(u32_parse_bytes(
                    file_bytes[var_index + 12..var_index + 16]
                        .try_into()
                        .unwrap(),
                )),
                ELFClass::Class64 => ELFAddress::ELF64(u64_parse_bytes(
                    file_bytes[var_index + 16..var_index + 24]
                        .try_into()
                        .unwrap(),
                )),
            },
        };

        println!("section header: {:#?}", section_header);

        section_headers.push(section_header);
    }

    if let Some(string_table_index) = section_header_string_table_index {
        // print string table names
        let string_table_start = match section_headers[string_table_index as usize].offset {
            ELFAddress::ELF64(x) => x as usize,
            ELFAddress::ELF32(x) => x as usize,
        };
        let string_table_end = match section_headers[string_table_index as usize].size {
            ELFAddress::ELF64(x) => x as usize,
            ELFAddress::ELF32(x) => x as usize,
        } + string_table_start;
        for section_header in section_headers {
            println!("Section name: {}", unsafe {
                get_string(
                    &file_bytes,
                    string_table_start + section_header.name as usize,
                    string_table_end,
                )
            });
        }
    }
}

/// Parses the first section header in bytes according to the special rules for the first section header.
///
/// Returns the first section header, the number of entires in the section header table and the index of the section name string table if it exists
fn parse_first_section_header(
    bytes: &[u8],
    elf_header: ELFHeader,
    class: ELFClass,
    endianness: ELFData,
) -> (ELFSectionHeader, u64, Option<u32>) {
    // first parse the first section header because it is special
    let var_index = match class {
        ELFClass::ClassNone => unreachable!(),
        ELFClass::Class32 => 24,
        ELFClass::Class64 => 40,
    };

    let (u16_parse_bytes, u32_parse_bytes, u64_parse_bytes) = get_parse_functions(endianness);

    let first_section_header = ELFSectionHeader {
        name: u32_parse_bytes(bytes[0..4].try_into().unwrap()),
        section_type: match u32_parse_bytes(bytes[4..8].try_into().unwrap()) {
            0 => ELFSectionType::Null,
            1 => ELFSectionType::ProgramBits,
            2 => ELFSectionType::SymbolTable,
            3 => ELFSectionType::StringTable,
            4 => ELFSectionType::RelocationWithAddends,
            5 => ELFSectionType::SymbolHashTable,
            6 => ELFSectionType::Dynamic,
            7 => ELFSectionType::Note,
            8 => ELFSectionType::NoBits,
            9 => ELFSectionType::Relocation,
            10 => ELFSectionType::SHLIB,
            11 => ELFSectionType::DynamicLinkingSymbolTable,
            14 => ELFSectionType::InitArray,
            15 => ELFSectionType::FiniArray,
            16 => ELFSectionType::PreInitArray,
            17 => ELFSectionType::Group,
            18 => ELFSectionType::SYMTABSHNDX,
            _ => ELFSectionType::Null, // TODO special section types
        },
        flags: match class {
            ELFClass::ClassNone => unreachable!(),
            ELFClass::Class32 => {
                ELFAddress::ELF32(u32_parse_bytes(bytes[8..12].try_into().unwrap()))
            }
            ELFClass::Class64 => {
                ELFAddress::ELF64(u64_parse_bytes(bytes[8..16].try_into().unwrap()))
            }
        },
        address: match class {
            ELFClass::ClassNone => unreachable!(),
            ELFClass::Class32 => {
                ELFAddress::ELF32(u32_parse_bytes(bytes[12..16].try_into().unwrap()))
            }
            ELFClass::Class64 => {
                ELFAddress::ELF64(u64_parse_bytes(bytes[16..24].try_into().unwrap()))
            }
        },
        offset: match class {
            ELFClass::ClassNone => unreachable!(),
            ELFClass::Class32 => {
                ELFAddress::ELF32(u32_parse_bytes(bytes[16..24].try_into().unwrap()))
            }
            ELFClass::Class64 => {
                ELFAddress::ELF64(u64_parse_bytes(bytes[24..32].try_into().unwrap()))
            }
        },
        size: match class {
            ELFClass::ClassNone => unreachable!(),
            ELFClass::Class32 => {
                ELFAddress::ELF32(u32_parse_bytes(bytes[20..24].try_into().unwrap()))
            }
            ELFClass::Class64 => {
                ELFAddress::ELF64(u64_parse_bytes(bytes[32..40].try_into().unwrap()))
            }
        },
        link: u32_parse_bytes(bytes[var_index..var_index + 4].try_into().unwrap()),
        info: u32_parse_bytes(bytes[var_index + 4..var_index + 8].try_into().unwrap()),
        address_alignment: match class {
            ELFClass::ClassNone => unreachable!(),
            ELFClass::Class32 => ELFAddress::ELF32(u32_parse_bytes(
                bytes[var_index + 8..var_index + 12].try_into().unwrap(),
            )),
            ELFClass::Class64 => ELFAddress::ELF64(u64_parse_bytes(
                bytes[var_index + 8..var_index + 16].try_into().unwrap(),
            )),
        },
        entry_size: match class {
            ELFClass::ClassNone => unreachable!(),
            ELFClass::Class32 => ELFAddress::ELF32(u32_parse_bytes(
                bytes[var_index + 12..var_index + 16].try_into().unwrap(),
            )),
            ELFClass::Class64 => ELFAddress::ELF64(u64_parse_bytes(
                bytes[var_index + 16..var_index + 24].try_into().unwrap(),
            )),
        },
    };
    if first_section_header.name != 0 {
        println!(
            "unknown data contained in first section header name: {}, exiting.",
            first_section_header.name
        );
        std::process::exit(0);
    }
    if first_section_header.section_type != ELFSectionType::Null {
        println!(
            "unknown data contained in first section header type: {:#?}, exiting.",
            first_section_header.section_type
        );
        std::process::exit(0);
    }

    // the bits of the flag data in the first section header, extended to 64 bits
    let flag = match first_section_header.flags {
        ELFAddress::ELF64(x) => x as u64,
        ELFAddress::ELF32(x) => x as u64,
    };
    if flag != 0 {
        println!(
            "unknown data contained in first section header flags: {}, exiting.",
            flag
        );
        std::process::exit(0);
    }

    let address = match first_section_header.address {
        ELFAddress::ELF64(x) => x as u64,
        ELFAddress::ELF32(x) => x as u64,
    };
    if address != 0 {
        println!(
            "unknown data contained in first section header flags: {}, exiting.",
            address
        );
        std::process::exit(0);
    }

    let offset = match first_section_header.offset {
        ELFAddress::ELF64(x) => x as u64,
        ELFAddress::ELF32(x) => x as u64,
    };
    if offset != 0 {
        println!(
            "unknown data contained in first section header flags: {}, exiting.",
            offset
        );
        std::process::exit(0);
    }

    let address_alignment = match first_section_header.address_alignment {
        ELFAddress::ELF64(x) => x as u64,
        ELFAddress::ELF32(x) => x as u64,
    };
    if address_alignment != 0 {
        println!(
            "unknown data contained in first section header flags: {}, exiting.",
            address_alignment
        );
        std::process::exit(0);
    }

    let entry_size = match first_section_header.entry_size {
        ELFAddress::ELF64(x) => x as u64,
        ELFAddress::ELF32(x) => x as u64,
    };
    if entry_size != 0 {
        println!(
            "unknown data contained in first section header flags: {}, exiting.",
            entry_size
        );
        std::process::exit(0);
    }

    let size = match first_section_header.size {
        ELFAddress::ELF64(x) => x as u64,
        ELFAddress::ELF32(x) => x as u64,
    };

    // if the section header table size is in the first section header, the sh_size field is non zero and the
    // ELF headers shnum field is zero
    let section_header_entry_count = if size != 0 && elf_header.section_header_entry_count == 0 {
        size
    // if the section header table size is in the elf_header the first entry in the section header table has a zero sh_size field
    // in this case, the elf header may still have a zero e_shnum field indicating that there are zero sections in the file
    } else if size == 0 {
        elf_header.section_header_entry_count as u64
    // the first sections sh_size field and e_shnum field cannot both be non-zero
    } else {
        panic!("Section header table size conflict: elf header reports: {}, first section header reports: {}", elf_header.section_header_entry_count, size);
    };

    const SHN_UNDEF: u16 = 0;
    const SHN_XINDEX: u16 = 0xFFFF;

    let section_header_string_table_index =
        if elf_header.section_header_string_table_index == SHN_UNDEF {
            // the file has no section name string table
            None
        } else if elf_header.section_header_string_table_index == SHN_XINDEX {
            Some(first_section_header.link)
        } else {
            Some(elf_header.section_header_string_table_index as u32)
        };
    ( 
        first_section_header,
        section_header_entry_count,
        section_header_string_table_index,
    )
}

/// Gets appropriate parsing functions for u16, u32, and u64 based on the specified endianness.
///
/// Panics if endianness == ELFData::ELFDataNone.
fn get_parse_functions(
    endianness: ELFData,
) -> (fn([u8; 2]) -> u16, fn([u8; 4]) -> u32, fn([u8; 8]) -> u64) {
    let u16_parse_bytes = match endianness {
        ELFData::ELFDataNone => unreachable!(),
        ELFData::ELFData2LSB => u16::from_le_bytes,
        ELFData::ELFDATA2MSB => u16::from_be_bytes,
    };
    let u32_parse_bytes = match endianness {
        ELFData::ELFDataNone => unreachable!(),
        ELFData::ELFData2LSB => u32::from_le_bytes,
        ELFData::ELFDATA2MSB => u32::from_be_bytes,
    };
    let u64_parse_bytes = match endianness {
        ELFData::ELFDataNone => unreachable!(),
        ELFData::ELFData2LSB => u64::from_le_bytes,
        ELFData::ELFDATA2MSB => u64::from_be_bytes,
    };
    (u16_parse_bytes, u32_parse_bytes, u64_parse_bytes)
}

/// Parses the e_ident portion of an elf file starting at the beginning of bytes.
fn parse_e_ident(bytes: &[u8]) -> EIdent {
    if bytes.len() < 16 {
        panic!("file is too small to contain an ELF header!");
    }

    if bytes[0..4] != [0x7F, 0x45, 0x4C, 0x46] {
        panic!(
            "Not an ELF file\nexpected magic number: {:#?}\nfound: {},{},{},{}",
            [0x7F, 0x45, 0x4C, 0x46],
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3]
        );
    }

    EIdent {
        ei_mag: bytes[0..4].try_into().unwrap(),
        ei_class: match bytes[4] {
            0 => ELFClass::ClassNone,
            1 => ELFClass::Class32,
            2 => ELFClass::Class64,
            _ => panic!("unknown ELF Class (value: {})", bytes[4]),
        },
        ei_data: match bytes[5] {
            0 => ELFData::ELFDataNone,
            1 => ELFData::ELFData2LSB,
            2 => ELFData::ELFDATA2MSB,
            _ => panic!("unknown ELF Data (value: {})", bytes[5]),
        },
        ei_version: bytes[6],
        ei_os_abi: match bytes[7] {
            0 => ELFABI::None,
            3 => ELFABI::Linux,
            _ => panic!("unsupported API (value: {}", bytes[7]),
        },
        ei_abi_version: bytes[8],
        ei_pad: bytes[9..16].try_into().unwrap(),
    }
}

/// Parses an ELFHeader starting at the beginning of bytes using the specified class and data endianness.
///
/// Returns a tuple containing the elf header, and the index of the byte immediately following the header.
fn parse_header(bytes: &[u8], class: ELFClass, endianness: ELFData) -> (ELFHeader, usize) {
    // where the indices of the ELFHeader start after the variable length portion
    // the index of the first byte of flags
    let index = match class {
        ELFClass::Class32 => 20,
        ELFClass::Class64 => 32,
        ELFClass::ClassNone => {
            println!("ELFClass is None, unable to load more information");
            std::process::exit(0);
        }
    };

    if bytes.len() < index + 16 {
        panic!("bytes is not large enough to hold the elf header specified by class.\nbytes length: {}, expected size: {}", bytes.len(), index + 16);
    }

    let (u16_parse_bytes, u32_parse_bytes, u64_parse_bytes) = get_parse_functions(endianness);

    let elf_header = ELFHeader {
        e_type: match u16_parse_bytes(bytes[0..2].try_into().unwrap()) {
            0 => ELFType::None,
            1 => ELFType::Relocatable,
            2 => ELFType::Executable,
            3 => ELFType::SharedObject,
            4 => ELFType::Core,
            _ => ELFType::Other,
        },
        machine: match u16_parse_bytes(bytes[2..4].try_into().unwrap()) {
            0 => ELFMachine::None,
            3 => ELFMachine::I386,
            62 => ELFMachine::AMD64,
            _ => ELFMachine::Other,
        },
        version: u32_parse_bytes(bytes[4..8].try_into().unwrap()),
        entry_point: match class {
            ELFClass::ClassNone => unreachable!(),
            ELFClass::Class32 => {
                ELFAddress::ELF32(u32_parse_bytes(bytes[8..12].try_into().unwrap()))
            }
            ELFClass::Class64 => {
                ELFAddress::ELF64(u64_parse_bytes(bytes[8..16].try_into().unwrap()))
            }
        },
        program_header_offset: match class {
            ELFClass::ClassNone => unreachable!(),
            ELFClass::Class32 => {
                ELFAddress::ELF32(u32_parse_bytes(bytes[12..16].try_into().unwrap()))
            }
            ELFClass::Class64 => {
                ELFAddress::ELF64(u64_parse_bytes(bytes[16..24].try_into().unwrap()))
            }
        },
        section_header_offset: match class {
            ELFClass::ClassNone => unreachable!(),
            ELFClass::Class32 => {
                ELFAddress::ELF32(u32_parse_bytes(bytes[16..20].try_into().unwrap()))
            }
            ELFClass::Class64 => {
                ELFAddress::ELF64(u64_parse_bytes(bytes[24..32].try_into().unwrap()))
            }
        },
        flags: u32_parse_bytes(bytes[index..index + 4].try_into().unwrap()),
        header_size: u16_parse_bytes(bytes[index + 4..index + 6].try_into().unwrap()),
        program_header_entry_size: u16_parse_bytes(bytes[index + 6..index + 8].try_into().unwrap()),
        program_header_entry_count: u16_parse_bytes(
            bytes[index + 8..index + 10].try_into().unwrap(),
        ),
        section_header_entry_size: u16_parse_bytes(
            bytes[index + 10..index + 12].try_into().unwrap(),
        ),
        section_header_entry_count: u16_parse_bytes(
            bytes[index + 12..index + 14].try_into().unwrap(),
        ),
        section_header_string_table_index: u16_parse_bytes(
            bytes[index + 14..index + 16].try_into().unwrap(),
        ),
    };
    (elf_header, index + 16)
}

// TODO: refactor to improve safety
unsafe fn get_string(bytes: &[u8], start: usize, end: usize) -> String {
    let mut i = start;
    while bytes[i] != 0 {
        i += 1;
        if i >= end {
            panic!("index out of bounds! i: {} end: {}", i, end);
        }
    }
    let str = CStr::from_ptr(bytes.as_ptr().add(start) as *const i8)
        .to_str()
        .unwrap(); // TODO better error handling

    return str.to_owned(); // to_owned() probably not necessary TODO: fix
}
