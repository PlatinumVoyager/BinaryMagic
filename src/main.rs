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
use goblin::elf::Header;
use goblin::elf::header::*;
use goblin::strtab::Strtab;
use goblin::container::Endian;
use goblin::elf64::header::SIZEOF_IDENT;

type Context = goblin::container::Ctx;

/* Terminal styling options */
const OMEGA: &str = "\u{03a9}";
const CHECK: &str = "\u{2713}";
const CROSS: &str = "\u{2717}";

const PARAM_DATA_LIMIT: usize = 1;
const ELF_MAGIC_LEN: usize = 4;
const DEFAULT_PATH: &str = "/usr/bin/ls";

const SINGULAR_CALLER: bool = true;
const MULTI_CALLER: bool = !SINGULAR_CALLER;

enum ElfObjectType
{
    ET_NONE,
    ET_REL,
    ET_EXEC,
    ET_DYN,
    ET_CORE
}

impl ElfObjectType
{
    fn get_type(self: &Self) -> String
    {
        match *self
        {
            ElfObjectType::ET_NONE => return String::from("ET_NONE (No file type)"),
            ElfObjectType::ET_REL => return String::from("ET_REL (Relocatable file)"),
            ElfObjectType::ET_EXEC => return String::from("ET_EXEC (Executable file)"),
            ElfObjectType::ET_DYN => return String::from("ET_DYN (Shared object file)"),
            ElfObjectType::ET_CORE => return String::from("ET_CORE (Core file)")
        };
    }
}

struct Arguments 
{
    file: String,
    optional_param: String
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
            return todo!()
        }
    }


    fn parse_header_sections(self: &Self, elf_obj: &Elf, is_caller_singular: bool) -> ()
    {
        let elf_ctx: Context = Context::default();
        let elf_sz: usize = Header::size(elf_ctx);

        /* Section header string table */
        let elf_shdr_tab: &Strtab<'_> = &elf_obj.shdr_strtab;
        println!("\nSection Headers =>");

        let mut section_hdr_table: Table = Table::new();

        section_hdr_table.load_preset(UTF8_BORDERS_ONLY)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                /* Formatting options supplemented */
                Cell::new(format!("Symbol Name \u{00a7}")).fg(Color::Green).add_attribute(Attribute::Bold), 
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
        0 => ElfObjectType::ET_NONE,
        1 => ElfObjectType::ET_REL,
        2 => ElfObjectType::ET_EXEC,
        3 => ElfObjectType::ET_DYN,
        4 => ElfObjectType::ET_CORE,

        _ => ElfObjectType::ET_NONE
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

    if args[0].to_string() == String::from("help")
    {
        send_help();
    }

    Some(Arguments { 
        file: match (args.len() < 1) as bool 
        { 
            true => {
                send_help();

                println!("No FILE detected! Using default path: \"{DEFAULT_PATH}\" as entry point!");
                DEFAULT_PATH.to_string()
            },

            false => args[0].clone()
        },

        optional_param: match (args.len() >= 2) as bool { true => args[1].clone(), false => "NULL".to_string() }
    })
}


fn send_help() -> ()
{
    let help: &str = r##"
        BINARYMAGIC - v1.0 (ALPHA)
        ==========================
    
        Arguments:
        ----------
    
            --sections      view the section header table of the ELF32/ELF64 binary      
            --dyn-syms      view the dynamic symbol table of the ELF32/ELF64 binary
            --dyn-libs      view the dynamic library table of the ELF32/ELF64 binary
    "##;

    println!("{}", help.unindent());

    std::process::exit(0);
}