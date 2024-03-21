/*
 * Copyright (C) 2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019-2020 Nils Asmussen, Barkhausen Institut
 *
 * This file is part of M3 (Microkernel-based SysteM for Heterogeneous Manycores).
 *
 * M3 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * M3 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License version 2 for more details.
 */

//! Contains the basics of the ELF interface

use bitflags::bitflags;

use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::boxed::Box;
use crate::errors::{Code, Error};
use crate::io::{read_object, Read};
use crate::kif;

const EI_MAGIC: usize = 4;

/// The program header entry types
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[repr(u32)]
pub enum PHType {
    /// Load segment
    #[default]
    Load = 1,
}

bitflags! {
    /// The program header flags
    #[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
    pub struct PHFlags : u32 {
        /// Executable
        const X = 0x1;
        /// Writable
        const W = 0x2;
        /// Readable
        const R = 0x4;
    }
}

#[derive(Default, Debug)]
#[repr(C)]
pub struct ElfIdent {
    /// ELF magic: ['\x7F', 'E', 'L', 'F']
    pub magic: [u8; EI_MAGIC],
    // 1 = 32-bit, 2 = 64-bit
    pub class: u8,
    // endianess: 1 = little, 2 = big
    pub data: u8,
    // always 1
    pub version: u8,
    // OS ABI (0 = System V, 3 = Linux, ...)
    pub os_abi: u8,
    // further specifies the ABI
    pub abi_version: u8,
    pub _reserved: [u8; 7],
}

impl ElfIdent {
    /// Checks whether the magic is correct
    pub fn check_magic(&self) -> Result<(), Error> {
        if self.magic[0] != b'\x7F'
            || self.magic[1] != b'E'
            || self.magic[2] != b'L'
            || self.magic[3] != b'F'
        {
            Err(Error::new(Code::InvalidElf))
        }
        else {
            Ok(())
        }
    }
}

/// common ELF header
#[derive(Default, Debug)]
#[repr(C)]
pub struct ElfHeaderCommon {
    /// ELF ident
    pub ident: ElfIdent,
    /// ELF type (e.g., executable)
    pub ty: u16,
    /// Machine the ELF binary was built for
    pub machine: u16,
    /// ELF version
    pub version: u32,
}

impl ElfHeaderCommon {
    /// Load the actual ELF header from given reader.
    ///
    /// Depending on whether self.ident.class indicates a 32-bit or 64-bit ELF file, it will load
    /// the corresponding header.
    ///
    /// Note that this method assumes that the reader is at position 0.
    pub fn load_hdr(&self, r: &mut dyn Read) -> Result<Box<dyn ElfHeader>, Error> {
        if self.ident.class == 1 {
            Ok(Box::new(read_object::<ElfHeader32>(r)?) as Box<dyn ElfHeader>)
        }
        else {
            Ok(Box::new(read_object::<ElfHeader64>(r)?) as Box<dyn ElfHeader>)
        }
    }
}

/// Access to ISA-dependent header members
pub trait ElfHeader {
    /// Returns the entry point of the ELF file
    fn entry(&self) -> usize;

    /// Returns the program header offset
    fn ph_off(&self) -> usize;

    /// Returns the number of present program headers
    fn ph_num(&self) -> u16;

    /// Loads a program header from the given reader.
    ///
    /// Depending on the type of this ELF file it will load a ProgramHeader32 or ProgramHeader64.
    ///
    /// Note that this method assumes that the reader is at the correct position.
    fn load_ph(&self, r: &mut dyn Read) -> Result<Box<dyn ProgramHeader>, Error>;
}

/// ELF header for 64-bit binaries
#[derive(Default, Debug)]
#[repr(C)]
pub struct ElfHeader64 {
    /// ELF ident
    ident: ElfIdent,
    /// ELF type (e.g., executable)
    ty: u16,
    /// Machine the ELF binary was built for
    machine: u16,
    /// ELF version
    version: u32,
    /// Entry point of the program
    entry: u64,
    /// Program header offset
    ph_off: u64,
    /// Section header offset
    sh_off: u64,
    /// ELF flags
    flags: u32,
    /// Size of the ELF header
    eh_size: u16,
    /// Size of program headers
    ph_entry_size: u16,
    /// Number of program headers
    ph_num: u16,
    /// Size of section headers
    sh_entry_size: u16,
    /// Number of section headers
    sh_num: u16,
    /// Section header string table index
    sh_string_idx: u16,
}
const _: () = assert!(crate::mem::size_of::<ElfHeader64>() == 64);

impl ElfHeader for ElfHeader32 {
    fn entry(&self) -> usize {
        self.entry as usize
    }

    fn ph_off(&self) -> usize {
        self.ph_off as usize
    }

    fn ph_num(&self) -> u16 {
        self.ph_num
    }

    fn load_ph(&self, r: &mut dyn Read) -> Result<Box<dyn ProgramHeader>, Error> {
        Ok(Box::new(read_object::<ProgramHeader32>(r)?))
    }
}

/// ELF header for 32-bit binaries
#[derive(Default, Debug)]
#[repr(C)]
pub struct ElfHeader32 {
    /// ELF ident
    ident: ElfIdent,
    /// ELF type (e.g., executable)
    ty: u16,
    /// Machine the ELF binary was built for
    machine: u16,
    /// ELF version
    version: u32,
    /// Entry point of the program
    entry: u32,
    /// Program header offset
    ph_off: u32,
    /// Section header offset
    sh_off: u32,
    /// ELF flags
    flags: u32,
    /// Size of the ELF header
    eh_size: u16,
    /// Size of program headers
    ph_entry_size: u16,
    /// Number of program headers
    ph_num: u16,
    /// Size of section headers
    sh_entry_size: u16,
    /// Number of section headers
    sh_num: u16,
    /// Section header string table index
    sh_string_idx: u16,
}
const _: () = assert!(crate::mem::size_of::<ElfHeader32>() == 52);

impl ElfHeader for ElfHeader64 {
    fn entry(&self) -> usize {
        self.entry as usize
    }

    fn ph_off(&self) -> usize {
        self.ph_off as usize
    }

    fn ph_num(&self) -> u16 {
        self.ph_num
    }

    fn load_ph(&self, r: &mut dyn Read) -> Result<Box<dyn ProgramHeader>, Error> {
        Ok(Box::new(read_object::<ProgramHeader64>(r)?))
    }
}

/// Access to ISA-dependent program header members
pub trait ProgramHeader {
    /// Returns the program header type (see [`PHType`])
    fn ty(&self) -> u32;

    /// Returns the offset
    fn offset(&self) -> usize;

    /// Returns the virtual address
    fn virt_addr(&self) -> usize;

    /// Returns the physical address
    fn phys_addr(&self) -> usize;

    /// Returns the flags (see [`PHFlags`])
    fn flags(&self) -> u32;

    /// Returns the PH size in the file
    fn file_size(&self) -> usize;

    /// Returns the PH size in memory
    fn mem_size(&self) -> usize;
}

/// Program header for 32-bit ELF files
#[derive(Default, Debug)]
#[repr(C)]
pub struct ProgramHeader32 {
    /// Program header type
    ty: u32,
    /// File offset
    offset: u32,
    /// Virtual address
    virt_addr: u32,
    /// Physical address
    phys_addr: u32,
    /// Size of this program header in the file
    file_size: u32,
    /// Size of this program header in memory
    mem_size: u32,
    /// Program header flags
    flags: u32,
    /// Alignment
    align: u32,
}
const _: () = assert!(crate::mem::size_of::<ProgramHeader32>() == 32);

impl ProgramHeader for ProgramHeader32 {
    fn ty(&self) -> u32 {
        self.ty
    }

    fn offset(&self) -> usize {
        self.offset as usize
    }

    fn virt_addr(&self) -> usize {
        self.virt_addr as usize
    }

    fn phys_addr(&self) -> usize {
        self.phys_addr as usize
    }

    fn flags(&self) -> u32 {
        self.flags
    }

    fn file_size(&self) -> usize {
        self.file_size as usize
    }

    fn mem_size(&self) -> usize {
        self.mem_size as usize
    }
}

/// Program header for 64-bit ELF files
#[derive(Default, Debug)]
#[repr(C)]
pub struct ProgramHeader64 {
    /// Program header type
    ty: u32,
    /// Program header flags
    flags: u32,
    /// File offset
    offset: u64,
    /// Virtual address
    virt_addr: u64,
    /// Physical address
    phys_addr: u64,
    /// Size of this program header in the file
    file_size: u64,
    /// Size of this program header in memory
    mem_size: u64,
    /// Alignment
    align: u64,
}
const _: () = assert!(crate::mem::size_of::<ProgramHeader64>() == 56);

impl ProgramHeader for ProgramHeader64 {
    fn ty(&self) -> u32 {
        self.ty
    }

    fn offset(&self) -> usize {
        self.offset as usize
    }

    fn virt_addr(&self) -> usize {
        self.virt_addr as usize
    }

    fn phys_addr(&self) -> usize {
        self.phys_addr as usize
    }

    fn flags(&self) -> u32 {
        self.flags
    }

    fn file_size(&self) -> usize {
        self.file_size as usize
    }

    fn mem_size(&self) -> usize {
        self.mem_size as usize
    }
}

impl From<PHFlags> for kif::Perm {
    fn from(flags: PHFlags) -> Self {
        let mut prot = kif::Perm::empty();
        if flags.contains(PHFlags::R) {
            prot |= kif::Perm::R;
        }
        if flags.contains(PHFlags::W) {
            prot |= kif::Perm::W;
        }
        if flags.contains(PHFlags::X) {
            prot |= kif::Perm::X;
        }
        prot
    }
}
