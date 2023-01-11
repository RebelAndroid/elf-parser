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

    if file_bytes.len() < 16 {
        panic!("file is too small to contain an ELF header!");
    }

    if file_bytes[0..4] != [0x7F, 0x45, 0x4C, 0x46] {
        panic!(
            "Not an ELF file\nexpected magic number: {:#?}\nfound: {},{},{},{}",
            [0x7F, 0x45, 0x4C, 0x46],
            file_bytes[0],file_bytes[1],file_bytes[2],file_bytes[3]
        );
    }

    let e_ident: EIdent = EIdent {
        ei_mag: file_bytes[0..4].try_into().unwrap(),
        ei_class: match file_bytes[4] {
            0 => ELFClass::ClassNone,
            1 => ELFClass::Class32,
            2 => ELFClass::Class64,
            _ => panic!("unknown ELF Class (value: {})", file_bytes[4]),
        },
        ei_data: match file_bytes[5] {
            0 => ELFData::ELFDataNone,
            1 => ELFData::ELFData2LSB,
            2 => ELFData::ELFDATA2MSB,
            _ => panic!("unknown ELF Data (value: {})", file_bytes[5]),
        },
        ei_version: file_bytes[6],
        ei_os_abi: match file_bytes[7] {
            0 => ELFABI::None,
            3 => ELFABI::Linux,
            _ => panic!("unsupported API (value: {}", file_bytes[7]),
        },
        ei_abi_version: file_bytes[8],
        ei_pad: file_bytes[9..16].try_into().unwrap(),
    };
    
    if e_ident.ei_pad != [0; 7] {
        println!(
            "unknown data in padding: {:#?}\nExpected: {:#?}",
            e_ident.ei_pad, [0; 7]
        );
    }
    println!("ELF identification information:\n{:#?}", e_ident);

    if (e_ident.ei_class == ELFClass::ClassNone) {}

    // where the indices of the ELFHeader start after the variable length portion
    // the index of the first byte of flags
    let index = match e_ident.ei_class {
        ELFClass::Class32 => 36,
        ELFClass::Class64 => 48,
        ELFClass::ClassNone => {
            println!("ELFClass is None, unable to load more information");
            std::process::exit(0);
        }
    };

    let u16_parse_bytes = match e_ident.ei_data {
        ELFData::ELFDataNone => unreachable!(),
        ELFData::ELFData2LSB => u16::from_le_bytes,
        ELFData::ELFDATA2MSB => u16::from_be_bytes,
    };
    let u32_parse_bytes = match e_ident.ei_data {
        ELFData::ELFDataNone => unreachable!(),
        ELFData::ELFData2LSB => u32::from_le_bytes,
        ELFData::ELFDATA2MSB => u32::from_be_bytes,
    };
    let u64_parse_bytes = match e_ident.ei_data {
        ELFData::ELFDataNone => unreachable!(),
        ELFData::ELFData2LSB => u64::from_le_bytes,
        ELFData::ELFDATA2MSB => u64::from_be_bytes,
    };

    let elf_header = ELFHeader {
        e_type: match u16_parse_bytes(file_bytes[16..18].try_into().unwrap()) {
            0 => ELFType::None,
            1 => ELFType::Relocatable,
            2 => ELFType::Executable,
            3 => ELFType::SharedObject,
            4 => ELFType::Core,
            _ => ELFType::Other,
        },
        machine: match u16_parse_bytes(file_bytes[18..20].try_into().unwrap()) {
            0 => ELFMachine::None,
            3 => ELFMachine::I386,
            62 => ELFMachine::AMD64,
            _ => ELFMachine::Other,
        },
        version: u32_parse_bytes(file_bytes[20..24].try_into().unwrap()),
        entry_point: match e_ident.ei_class {
            ELFClass::ClassNone => unreachable!(),
            ELFClass::Class32 => {
                ELFAddress::ELF32(u32_parse_bytes(file_bytes[24..28].try_into().unwrap()))
            }
            ELFClass::Class64 => {
                ELFAddress::ELF64(u64_parse_bytes(file_bytes[24..32].try_into().unwrap()))
            }
        },
        program_header_offset: match e_ident.ei_class {
            ELFClass::ClassNone => unreachable!(),
            ELFClass::Class32 => {
                ELFAddress::ELF32(u32_parse_bytes(file_bytes[28..32].try_into().unwrap()))
            }
            ELFClass::Class64 => {
                ELFAddress::ELF64(u64_parse_bytes(file_bytes[32..40].try_into().unwrap()))
            }
        },
        section_header_offset: match e_ident.ei_class {
            ELFClass::ClassNone => unreachable!(),
            ELFClass::Class32 => {
                ELFAddress::ELF32(u32_parse_bytes(file_bytes[32..36].try_into().unwrap()))
            }
            ELFClass::Class64 => {
                ELFAddress::ELF64(u64_parse_bytes(file_bytes[40..48].try_into().unwrap()))
            }
        },
        flags: u32_parse_bytes(file_bytes[index..index + 4].try_into().unwrap()),
        header_size: u16_parse_bytes(file_bytes[index + 4..index + 6].try_into().unwrap()),
        program_header_entry_size: u16_parse_bytes(
            file_bytes[index + 6..index + 8].try_into().unwrap(),
        ),
        program_header_entry_count: u16_parse_bytes(
            file_bytes[index + 8..index + 10].try_into().unwrap(),
        ),
        section_header_entry_size: u16_parse_bytes(
            file_bytes[index + 10..index + 12].try_into().unwrap(),
        ),
        section_header_entry_count: u16_parse_bytes(
            file_bytes[index + 12..index + 14].try_into().unwrap(),
        ),
        section_header_string_table_index: u16_parse_bytes(
            file_bytes[index + 14..index + 16].try_into().unwrap(),
        ),
    };
    println!("ELF Header info:\n{:#?}", elf_header);
    // TODO: Handle files with section header counts greater than SHN_LORESERVE (65280)

    // index of the first byte after the end of the section header
    let section_header_end: u64 = match elf_header.section_header_offset {
        ELFAddress::ELF64(x) => x,
        ELFAddress::ELF32(x) => x as u64,
    } + elf_header.section_header_entry_count as u64
        * elf_header.section_header_entry_size as u64;

    if (file_bytes.len() as u64) < section_header_end {
        panic!("section header goes beyond end of file! Length of file: {}, expected end of header_file: {}", file_bytes.len(), section_header_end);
    }

    let mut section_headers: Vec<ELFSectionHeader> = vec![];

    for section_header_index in 0..elf_header.section_header_entry_count {
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

    let string_table_start =
        match section_headers[elf_header.section_header_string_table_index as usize].offset {
            ELFAddress::ELF64(x) => x as usize,
            ELFAddress::ELF32(x) => x as usize,
        };
    let string_table_end =
        match section_headers[elf_header.section_header_string_table_index as usize].size {
            ELFAddress::ELF64(x) => x as usize,
            ELFAddress::ELF32(x) => x as usize,
        } + string_table_start;
    for section_header in section_headers {
        println!("Section name: {}", unsafe {
            get_string(&file_bytes, string_table_start + section_header.name as usize, string_table_end)
        });
    }
}

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
