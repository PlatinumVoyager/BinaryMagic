/*
    2023 The BinaryMagic Authors.

    GNU PL 3.0 (GPL-3.0) - All rights reserved.
*/

use std::fs;
use std::env;
use std::path::Path;
use std::collections::HashMap;

use unindent::Unindent;

use comfy_table::*;
use comfy_table::presets::UTF8_BORDERS_ONLY;

use goblin::Object;
use goblin::elf::Elf;
use goblin::elf::header::*;
use goblin::strtab::Strtab;
use goblin::container::Endian;
use goblin::elf64::header::SIZEOF_IDENT;

/* Import all pre-defined elf section header flag attribute values */
use goblin::elf64::section_header::*;

/* Custom section header flags */
const SHF_WRITE_ALLOC: u32 = SHF_WRITE | SHF_ALLOC;
const SHF_ASM_INST_ALLOC: u32 = SHF_ALLOC | SHF_EXECINSTR;

const SHF_UNDEFINED: u32 = 0; const SHF_UNDEFINED_STR: &str = "SHF_UNDEFINED";

/* Terminal styling options */
const OMEGA: &str = "\u{03a9}";
const CHECK: &str = "\u{2713}";
const CROSS: &str = "\u{2717}";

const PARAM_DATA_LIMIT: usize = 1;
const ELF_MAGIC_LEN: usize = 4;

const SINGULAR_CALLER: bool = true;
const MULTI_CALLER: bool = !SINGULAR_CALLER;

enum ElfSectionType
{
    ShtNull,            /* 0 = marks the section header as inactive */
    ShtProgBits,        /* 1 = holds information defined by the program, whose format and meaning are determined solely by the program */
    ShtSymTab,          /* 2 = hold a symbol table */
    ShtStrTab,          /* 3 = section holds a string table. An object file may have multiple string table sections */
    ShtRela,            /* 4 = section holds relocation entries with explicit addends, such as type Elf32_Rela for the 32-bit class of object files or type Elf64_Rela for the 64-bit class of object files */
    ShtHash,            /* 5 = section holds a symbol hash table. Currently, an object file may have only one hash table*/
    ShtDynamic,         /* 6 = section holds information for dynamic linking. Currently, an object file may have only one dynamic section */
    ShtNote,            /* 7 = section holds information that marks the file in some way */
    ShtNoBits,          /* 8 = section of this type occupies no space in the file but otherwise resembles ShtProgBits */
    ShtRel,             /* 9 = section holds relocation entries without explicit addends. An object file may have multiple relocation sections */
    ShtShLib,           /* 10 = section type is reserved but has unspecified semantics */
    ShtDynSym,          /* 11 = hold a symbol table */
    ShtInitArray,       /* 14 = section contains an array of pointers to initialization functions */
    ShtFiniArray,       /* 15 = section contains an array of pointers to termination functions */
    ShtPreInitArray,    /* 16 = section contains an array of pointers to functions that are invoked before all other initialization functions */
    ShtGroup,           /* 17 = section defines a section group. A section group is a set of sections that are related and that must be treated specially by the linker */
    ShtSymTabShndx,    /* 18 = section is associated with a section of type ShtSymTab and is required if any of the section header indexes referenced by that symbol table contain the escape value SHN_XINDEX */

    // ShtLoos,            /* 0x60000000 = values in this inclusive range are reserved for operating system-specific semantics */
    // ShtHios,            /* 0x6fffffff = values in this inclusive range are reserved for operating system-specific semantics */
    // ShtLoProc,          /* 0x70000000 = values in this inclusive range are reserved for processor-specific semantics */
    // ShtHiProc,          /* 0x7fffffff = values in this inclusive range are reserved for processor-specific semantics */    
    // ShtLoUser,          /* 0x80000000 = this value specifies the lower bound of the range of indexes reserved for application programs */
    // ShtHiUser           /* 0xffffffff = this value specifies the upper bound of the range of indexes reserved for application programs */
}

impl ElfSectionType 
{
    fn get_type(self: &Self) -> String
    {
        match *self
        {
            ElfSectionType::ShtNull => "SHT_NULL".to_string(),
            ElfSectionType::ShtProgBits => "SHT_PROGBITS".to_string(),
            ElfSectionType::ShtSymTab => "SHT_SYMTAB".to_string(),
            ElfSectionType::ShtStrTab => "SHT_STRTAB".to_string(),
            ElfSectionType::ShtRela => "SHT_RELA".to_string(),
            ElfSectionType::ShtHash => "SHT_HASH".to_string(),
            ElfSectionType::ShtDynamic => "SHT_DYNAMIC".to_string(),
            ElfSectionType::ShtNote => "SHT_NOTE".to_string(),
            ElfSectionType::ShtNoBits => "SHT_NOBITS".to_string(),
            ElfSectionType::ShtRel => "SHT_REL".to_string(),
            ElfSectionType::ShtShLib => "SHT_SHLIB".to_string(),
            ElfSectionType::ShtDynSym => "SHT_DYNSYM".to_string(),
            ElfSectionType::ShtInitArray => "SHT_INIT_ARRAY".to_string(),
            ElfSectionType::ShtFiniArray => "SHT_FINI_ARRAY".to_string(),
            ElfSectionType::ShtPreInitArray => "SHT_PREINIT_ARRAY".to_string(),
            ElfSectionType::ShtGroup => "SHT_GROUP".to_string(),
            ElfSectionType::ShtSymTabShndx => "SHT_SYMTAB_SHNDX".to_string(),
        }
    }
}

enum ElfObjectType
{
    EtNone,
    EtRel,
    EtExec,
    EtDyn,
    EtCore
}

impl ElfObjectType
{
    fn get_type(self: &Self) -> String
    {
        match *self
        {
            ElfObjectType::EtNone => return String::from("ET_NONE (No file type)"),
            ElfObjectType::EtRel => return String::from("ET_REL (Relocatable file)"),
            ElfObjectType::EtExec => return String::from("ET_EXEC (Executable file)"),
            ElfObjectType::EtDyn => return String::from("ET_DYN (Shared object file)"),
            ElfObjectType::EtCore => return String::from("ET_CORE (Core file)")
        };
    }
}

enum ProgramArgumentMethod
{
    Sections,
    DynamicSymbols,
    DynamicLibraries
}

impl ProgramArgumentMethod
{
    fn start_method_selector(self: &Self, args: &Arguments, elf_obj: &Elf) -> ()
    {
        match &self
        {
            ProgramArgumentMethod::Sections => args.parse_header_sections(&elf_obj, SINGULAR_CALLER),
            ProgramArgumentMethod::DynamicSymbols => args.parse_dynamic_syms(&elf_obj, SINGULAR_CALLER),

            ProgramArgumentMethod::DynamicLibraries => { 
                let libs: HashMap<String, _> = args.parse_dynamic_libs(&elf_obj);
                
                args.print_dynamic_libs(libs);
                std::process::exit(0);
            }
        }
    }
}

/* CLI options */
struct Arguments 
{
    file: String,
    optional_param: String
}

impl Arguments
{
    fn initialize_primary_object(self: &Self, target: &Vec<u8>, argument: &&str, args: &Arguments) -> ()
    {
        /* Clone vector containing binary contents of the target executable */
        let target_clone: Vec<u8> = target.clone();

        // convert data to Elf
        if let Ok(Object::Elf(obj)) = Object::parse(&target_clone)
        {
            let start_enum: ProgramArgumentMethod;

            match argument
            {
                &"--sections" => start_enum = ProgramArgumentMethod::Sections,
                &"--dyn-syms" => start_enum = ProgramArgumentMethod::DynamicSymbols,
                &"--dyn-libs" => start_enum = ProgramArgumentMethod::DynamicLibraries,

                /* Default throwback value if it is somehow not already specified previously */
                _ => start_enum = ProgramArgumentMethod::Sections
            }

            start_enum.start_method_selector(&args, &obj);
        }
        else 
        {
            eprintln!("Object file is not supported at the moment!");
            std::process::exit(-1);
        }
    }


    fn parse_header_sections(self: &Self, elf_obj: &Elf, is_caller_singular: bool) -> ()
    {
        /* Section header string table */
        let elf_shdr_tab: &Strtab<'_> = &elf_obj.shdr_strtab;
        println!("\nSection Headers =>");

        let mut section_hdr_table: Table = Table::new();

        section_hdr_table.load_preset(UTF8_BORDERS_ONLY)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                /* Formatting options supplemented */
                Cell::new("Symbol Name \u{00a7}").fg(Color::Green).add_attribute(Attribute::Bold), 
                Cell::new("Flags").fg(Color::Green).add_attribute(Attribute::Bold),
                Cell::new("Header Type").fg(Color::Green).add_attribute(Attribute::Bold),
                Cell::new(format!("Offset {OMEGA}")).fg(Color::Green).add_attribute(Attribute::Bold),

                /* No formatting options */
                Cell::new("Size").fg(Color::Green).add_attribute(Attribute::Bold), 
                Cell::new("Ent size").fg(Color::Green).add_attribute(Attribute::Bold), 
                Cell::new("Has Table?").fg(Color::Green).add_attribute(Attribute::Bold)
            ]);
        
        for elf_section_hdr in &elf_obj.section_headers
        {
            let section_name: &str = elf_shdr_tab.get_at(elf_section_hdr.sh_name).unwrap_or("Not defined");
            let section_offset: String = format!("{}", elf_section_hdr.sh_offset);

            /* ELF section header type */
            let elf_sh_type: ElfSectionType = match elf_section_hdr.sh_type as u32 
            {
                SHT_NULL => ElfSectionType::ShtNull,
                SHT_PROGBITS => ElfSectionType::ShtProgBits,
                SHT_SYMTAB => ElfSectionType::ShtSymTab,
                SHT_STRTAB => ElfSectionType::ShtStrTab,
                SHT_RELA => ElfSectionType::ShtRela,
                SHT_HASH => ElfSectionType::ShtHash,
                SHT_DYNAMIC => ElfSectionType::ShtDynamic,
                SHT_NOTE => ElfSectionType::ShtNote,
                SHT_NOBITS => ElfSectionType::ShtNoBits,
                SHT_REL => ElfSectionType::ShtRel,
                SHT_SHLIB => ElfSectionType::ShtShLib,
                SHT_DYNSYM => ElfSectionType::ShtDynSym,
                SHT_INIT_ARRAY => ElfSectionType::ShtInitArray,
                SHT_FINI_ARRAY => ElfSectionType::ShtFiniArray,
                SHT_PREINIT_ARRAY => ElfSectionType::ShtPreInitArray,
                SHT_GROUP => ElfSectionType::ShtGroup,
                SHT_SYMTAB_SHNDX => ElfSectionType::ShtSymTabShndx,

                _  => ElfSectionType::ShtNull
            };

            let section_hdr_sz: String = format!("{}", match (elf_section_hdr.sh_size >= 1024 as u64) as bool {
                true => format!("{} Kb ({:.2} bytes)", ((&elf_section_hdr.sh_size / 1024) as f64), elf_section_hdr.sh_size),
                false => format!("{} bytes", &elf_section_hdr.sh_size)
            });

            let section_ent_sz: String = format!("{} bytes", elf_section_hdr.sh_entsize); 

            let _attributes: Vec<Attribute> = vec![
                // Attribute::Bold,
                // Attribute::Italic
            ];

            section_hdr_table.add_row(vec![
                Cell::new(section_name).fg(Color::DarkGrey).add_attribute(Attribute::Bold),  /* SECTION NAME */
                Cell::new(format!("{}", 
                    match elf_section_hdr.sh_flags as u32
                    {
                        SHF_UNDEFINED => SHF_UNDEFINED_STR,

                        /* handle write/allocation primary flags */
                        SHF_WRITE => "SHF_WRITE",
                        SHF_ALLOC => "SHF_ALLOC",
                        SHF_WRITE_ALLOC => "SHF_WRITE & SHF_ALLOC",

                        /* assembly instructions (intel/at&t)? */
                        SHF_ASM_INST_ALLOC => "SHF_ASM_OPCODE",

                        SHF_EXECINSTR => "SHF_EXECINSTR",
                        SHF_MERGE => "SHF_MERGE",
                        SHF_STRINGS => "SHF_STRINGS",
                        SHF_INFO_LINK => "SHF_INFO_LINK",
                        SHF_LINK_ORDER => "SHF_LINK_ORDER",
                        SHF_OS_NONCONFORMING => "SHF_OS_NON_CONFORMING",
                        SHF_GROUP => "SHF_GROUP",
                        SHF_TLS => "SHF_TLS",
                        SHF_MASKOS => "SHF_MASKOS",
                        SHF_MASKPROC => "SHF_MASKPROC",
                        
                        /* lazy method to handle bogus data */
                        _ => SHF_UNDEFINED_STR
                    }
                )).fg(Color::Yellow),

                Cell::new(&elf_sh_type.get_type()).fg(Color::DarkGreen).add_attribute(Attribute::Italic), 
                Cell::new(&section_offset),                                                  /* OFFSET  */
                Cell::new(&section_hdr_sz),                                                  /* HDR_SIZE */
                
                match (elf_section_hdr.sh_entsize > 0) as bool                               /* ENT_SIZE */
                {
                    true => Cell::new(&section_ent_sz),
                    false => Cell::new("")
                },                                  

                match (elf_section_hdr.sh_entsize > 0) as bool                               /* Has Table? */
                {
                    true => Cell::new(format!("{CHECK}")).fg(Color::Green).add_attribute(Attribute::Bold),
                    false => Cell::new(format!("{CROSS}")).fg(Color::Red).add_attribute(Attribute::Dim)
                } 
            ]);
        }

        println!("\n{section_hdr_table}");
        println!("\n{} section headers detected.", (&elf_obj.header.e_shnum - 1 as u16));

        match is_caller_singular
        {
            SINGULAR_CALLER => std::process::exit(0),
            MULTI_CALLER => ()
        }
    }


    fn parse_dynamic_syms(self: &Self, elf_obj: &Elf, is_caller_singular: bool) -> ()
    {
        /* Dynamically accessible symbols table */
        let elf_dym_sym: &Strtab<'_> = &elf_obj.dynstrtab;
        let elf_dymsym_vec: Vec<&str> = elf_dym_sym.to_vec().expect("Failed to convert dynamic symbol table to vector!");
        
        let mut c: i32 = 0;

        for (_, &v) in elf_dymsym_vec.iter().enumerate()
        {
            println!("\t {v}");
            c += 1;
        }

        println!("\n[DYNSYMS] {c} dynamic symbols found.");
        self.print_dynamic_libs(self.parse_dynamic_libs(&elf_obj));

        match is_caller_singular
        {
            SINGULAR_CALLER => std::process::exit(0),
            MULTI_CALLER => ()
        }
    }


    /* Return the current listing of dynamic libraries associated with the binary */
    fn parse_dynamic_libs(self: &Self, elf: &Elf) -> HashMap<String, ()>
    {
        let mut dyn_libs: HashMap<String, _> = HashMap::new();

        for lib in &elf.libraries
        {
            let x: String = lib.to_string();

            dyn_libs.insert(x, ());
        }

        dyn_libs
    }


    fn print_dynamic_libs(self: &Self, libs: HashMap<String, ()>) -> ()
    {
        {
            println!("\n* Dynamic Libraries found:");

            for libs in libs
            {
                println!("\ttarget >> {}", libs.0);
            }
        }

        ()
    }
}


fn main() -> Result<(), Box<dyn std::error::Error>>
{
    let argv: Arguments = parse_args().unwrap();

    // &str = stack allocation, String = heap allocation??
    let params: Vec<&str> = vec![
        "--sections",       /* ELF header section table */
        "--dyn-syms",       /* Dynamic symbols */    
        "--dyn-libs",       /* Dynamically linked libraries */
        "NULL"
    ];

    let path: &Path = Path::new(argv.file.as_str());
    let binary_fluff: Vec<u8> = fs::read(path).expect("Failed to read file data!");

    if argv.optional_param.len() >= PARAM_DATA_LIMIT
    {
        match params.iter().find(|x: &&&str| &argv.optional_param == **x)
        {
            Some(arg) => {
                match arg {
                    // &"--sections" because 'e = &&str', "--sections" = &str, so &"--sections" = &&str
                    &"--sections" | 
                    &"--dyn-syms" | &"--dyn-libs" => argv.initialize_primary_object(&binary_fluff, *(&arg), &argv),
                   
                    _ => ()
                }
            },

            None => {
                eprintln!("Error - unknown option: \"{}\"", argv.optional_param);
                std::process::exit(-1);
            }
        };
    }

    match Object::parse(&binary_fluff).expect("Failed to parse binary object file!")
    {
        Object::Elf(elf_obj) =>
        {
            argv.parse_header_sections(&elf_obj, MULTI_CALLER);
            argv.parse_dynamic_syms(&elf_obj, MULTI_CALLER);

            let elf_sz: u16 = elf_obj.header.e_ehsize;

            let elf_end: Endian = elf_obj.header.endianness().expect("Failed to obtain endianness of binary!");
            let elf_ident: [u8; SIZEOF_IDENT] = elf_obj.header.e_ident;

            let elf_emachine: u16 = elf_obj.header.e_machine;
            let elf_eversion: u32 = elf_obj.header.e_version;

            let (elf_magic, elf_class, elf_data, elf_version): (String, u8, u8, u8) = return_hdr_magic(&elf_ident);

            let msg: String = format!(r###"
                FILE HEADER/MAGIC INFORMATION
                =============================

                ARCH   : {elf_sz}-bit binary
                MAGIC  : {}
                         CLASS={} | DATA={} | VERSION={}

                ENDIAN : {:#?}
                E_TYPE : {}
                E_MACH : {}
                E_VERS : {}
                E_ENTR : {}
                ________________________
            "###, 
                elf_magic,                          /* MAGIC */
                match elf_class as u8               /* CLASS TYPE */
                {
                    ELFCLASSNONE => format!("{ELFCLASSNONE} (NONE)"), 
                    ELFCLASS32 => format!("{ELFCLASS32} (32 BIT)"),
                    ELFCLASS64 => format!("{ELFCLASS64} (64 BIT)"), 
                    
                    _ => String::from("UNKNOWN")
                },
                
                match elf_data as u8                /* DATA TYPE */
                {
                    ELFDATANONE => format!("{ELFDATANONE} (Invalid data encoding)"),
                    ELFDATA2LSB => format!("{ELFDATA2LSB} (LE with 2\'s complement)"),
                    ELFDATA2MSB => format!("{ELFDATA2MSB} (BE with 2\'s compliment)"),
               
                    _ => String::from("UNKNOWN")
                },

                elf_version,
                elf_end,                            /* ENDIAN TYPE */
                return_elf_etype(&elf_obj),         /* E_TYPE (Object file type) */
                return_elf_emachine(elf_emachine),  /* E_MACH (CPU Architecture)*/
                
                match elf_eversion as u32           /* E_VERS */
                { 
                    0 => format!("{elf_eversion} (EV_NONE)"), 
                    1 => format!("{elf_eversion} (EV_CURRENT)"),

                    _ => String::from("UNKNOWN")
                },

                elf_obj.entry,                      /* ENTRY POINT */
            );

            print!("{}", msg.unindent());
        },

        Object::PE(pe) => println!("pe: {:#?}", &pe),
        Object::Mach(mach) => println!("mach: {:#?}", &mach),
        Object::Unknown(magic) => println!("Invalid executable: could not parse file header: magic => {:#?}", magic),

        _ => ()
    };

    return Ok(())
}


fn return_elf_emachine(emachine_id: u16) -> String
{
    match emachine_id as u16
    {
        EM_NONE => "No machine".to_string(),
        EM_MIPS => "MIPS I Architecture".to_string(),
        EM_PPC | EM_PPC64 => "PowerPC 32/64 bit".to_string(),
        EM_X86_64 => "Intel/AMD 64-bit".to_string(),

        _ => "Unknown".to_string()
    }
}


fn return_elf_etype(elf: &Elf) -> String 
{
    let hdr_etype: u16 = elf.header.e_type;
            
    let etype_variant: ElfObjectType = match hdr_etype as u16
    {
        0 => ElfObjectType::EtNone,
        1 => ElfObjectType::EtRel,
        2 => ElfObjectType::EtExec,
        3 => ElfObjectType::EtDyn,
        4 => ElfObjectType::EtCore,

        _ => ElfObjectType::EtNone
    };

    etype_variant.get_type()
}


fn return_hdr_magic(magic: &[u8; 16]) -> (String, u8, u8, u8)
{
    let (
        elf_mag0, elf_mag1, elf_mag2, elf_mag3,
        elf_class, elf_data, elf_version
    ): 
    (&u8, u8, u8, u8, u8, u8, u8) = (
        &magic[0], // 0x7f
        magic[1],  // 'E'
        magic[2],  // 'L'
        magic[3],  // 'F',
        magic[4],  // CLASS
        magic[5],  // DATA 
        magic[6]   // VERSION
    );

    let mut i: usize = 0;
    let mut magic_vector: Vec<String> = Vec::new();

    while i < ELF_MAGIC_LEN
    {
        /* Start ELF MAGIC struct packing operations */
        match i as i32 
        {
            0 => { println!("\n* Packing ELFMAG0 => {elf_mag0}"); magic_vector.push(format!("{:02x?}", elf_mag0)) },
            1 => { println!("* Packing ELFMAG1 => {elf_mag1} ({})", elf_mag1 as char); magic_vector.push(format!("{:02x?}", elf_mag1)) },
            2 => { println!("* Packing ELFMAG2 => {elf_mag2} ({})", elf_mag2 as char); magic_vector.push(format!("{:02x?}", elf_mag2)) },
            3 => { println!("* Packing ELFMAG3 => {elf_mag3} ({})\n", elf_mag3 as char); magic_vector.push(format!("{:02x?}", elf_mag3)) },

            _ => ()
        }
        
        i += 1;
    }

    for (mut i, v) in magic.into_iter().skip(ELF_MAGIC_LEN).enumerate()
    {
        let hex_pair: String = format!("{:02x?}", v);
     
        magic_vector.push(hex_pair);
        i += 1;

        if i == magic.len()
        {
            print!("\n");

            break;
        }
    }

    if magic_vector.len() < magic.len()
    {
        eprintln!("Error - vector (magic_vector) and vector (magic) don\'t match in length!");

        std::process::exit(-1);
    }

    (magic_vector.join(" "), elf_class, elf_data, elf_version)
}


fn parse_args() -> Option<Arguments>
{
    let args: Vec<String> = env::args().skip(1).collect();

    Some(Arguments { 
        file: match (args.len() < 1) as bool 
        { 
            true => {
                send_help();
                "NULL".to_string()
            },

            false => args[0].clone()
        },

        optional_param: match (args.len() >= 2) as bool { true => args[1].clone(), false => "NULL".to_string() }
    })
}


fn send_help() -> ()
{
    let help: &str = r##"
        BINARYMAGIC - v1.1 (ALPHA)
        ==========================
    
        Arguments:
        ----------

            --help/-h       show this informational text and exit
            --sections      view the section header table of the ELF32/ELF64 binary      
            --dyn-syms      view the dynamic symbol table of the ELF32/ELF64 binary
            --dyn-libs      view the dynamic library table of the ELF32/ELF64 binary
    "##;

    println!("{}", help.unindent());

    std::process::exit(0);
}