use std::{env, fs::File, io::Read};

struct EIdent {
    ei_mag: [u8; 4],
    ei_class: u8,
    ei_data: u8,
    ei_version: u8,
    ei_os_abi: u8,
    ei_abi_version: u8,
    ei_pad: [u8; 7],
}

#[derive(PartialEq)]
enum ELFClass {
    ClassNone,
    Class32,
    Class64,
}

enum ELFData {
    //ELFDataNone,
    ELFData2LSB,
    ELFDATA2MSB,
}

enum ELFABI{
    NONE,
    LINUX,
}

struct ELFHeader32{
    e_type: u16,
    machine: u16,
    version: u32,
    entry_point: u32,
    program_header_offset: u32,
    section_header_offset: u32,
    flags: u32,
    header_size: u16,
    program_header_entry_size: u16,
    program_header_entry_count: u16,
    section_header_entry_size: u16,
    section_header_entry_count: u16,
    section_header_string_index: u16,
}

struct ELFHeader64{
    e_type: u16,
    machine: u16,
    version: u32,
    entry_point: u64,
    program_header_offset: u64,
    section_header_offset: u64,
    flags: u32,
    header_size: u16,
    program_header_entry_size: u16,
    program_header_entry_count: u16,
    section_header_entry_size: u16,
    section_header_entry_count: u16,
    section_header_string_index: u16,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let file = File::open(&args[1]).unwrap();
    let file_bytes: Vec<u8> = file.bytes().map(|byte| byte.unwrap()).collect();

    if file_bytes.len() < 16 {
        panic!("file is too small to contain an ELF header!");
    }
    // take first 16 bytes of file as e_ident
    let e_ident: EIdent = unsafe { std::mem::transmute::<[u8;16], EIdent>(file_bytes[0..16].try_into().unwrap())};
    if e_ident.ei_mag != [0x7F, 0x45, 0x4C, 0x46] {
        panic!(
            "invalid magic number\nexpected: {:#?}\nfound: {:#?}",
            [0x7F, 0x45, 0x4C, 0x46],
            e_ident.ei_mag
        );
    }
    let elf_class = match e_ident.ei_class {
        0 => ELFClass::ClassNone,
        1 => ELFClass::Class32,
        2 => ELFClass::Class64,
        _ => panic!("unknown ELF Class (value: {})", e_ident.ei_class),
    };

    let elf_data = match e_ident.ei_data {
        //0 => ELFData::ELFDataNone,
        1 => ELFData::ELFData2LSB,
        2 => ELFData::ELFDATA2MSB,
        _ => panic!("unknown ELF Data (value: {})", e_ident.ei_data),
    };

    if e_ident.ei_version != 1 {
        panic!("unknown ELF Version (value: {})", e_ident.ei_version);
    }

    let elf_abi = match e_ident.ei_os_abi{
        0 => ELFABI::NONE,
        3 => ELFABI::LINUX,
        _ => panic!("unsupported API (value: {}", e_ident.ei_os_abi),
    };

    if e_ident.ei_pad != [0; 7]{
        println!("unknown data in padding: {:#?}\nExpected: {:#?}", e_ident.ei_pad, [0; 7]);
    }

    if elf_class == ELFClass::Class32 {
        let elf_header: ELFHeader32 = unsafe{
            const HEADER_SIZE: usize = std::mem::size_of::<ELFHeader32>();
            std::mem::transmute::<[u8; HEADER_SIZE], ELFHeader32>(file_bytes[16..16 + HEADER_SIZE].try_into().unwrap())
        };
    }else if elf_class == ELFClass::Class64{
        let elf_header: ELFHeader64 = unsafe{
            const HEADER_SIZE: usize = std::mem::size_of::<ELFHeader64>();
            std::mem::transmute::<[u8; HEADER_SIZE], ELFHeader64>(file_bytes[16..16 + HEADER_SIZE].try_into().unwrap())
        };
    }else{
        panic!("unknown ELF class!")
    }

}
