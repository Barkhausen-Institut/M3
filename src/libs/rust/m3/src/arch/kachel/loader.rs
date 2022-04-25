/*
 * Copyright (C) 2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019-2022 Nils Asmussen, Barkhausen Institut
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

use core::{cmp, iter};

use crate::cfg;
use crate::col::Vec;
use crate::com::MemGate;
use crate::elf;
use crate::errors::{Code, Error};
use crate::goff;
use crate::io::{read_object, Read};
use crate::kif;
use crate::math;
use crate::mem::size_of;
use crate::session::MapFlags;
use crate::tiles::{Activity, Mapper};
use crate::vec;
use crate::vfs::{BufReader, File, FileRef, Seek, SeekMode};

extern "C" {
    static _start: u8;
    static _text_start: u8;
    static _text_end: u8;
    static _data_start: u8;
    static _bss_end: u8;
}

fn write_bytes_checked(
    mem: &MemGate,
    _vaddr: usize,
    data: *const u8,
    size: usize,
    offset: goff,
) -> Result<(), Error> {
    mem.write_bytes(data, size, offset)?;

    // on hw, validate whether the data has been written correctly by reading it again
    #[cfg(target_vendor = "hw")]
    {
        use crate::cell::StaticRefCell;

        static BUF: StaticRefCell<[u8; cfg::PAGE_SIZE]> = StaticRefCell::new([0u8; cfg::PAGE_SIZE]);

        let mut off = offset;
        let mut data_slice = unsafe { core::slice::from_raw_parts(data, size) };
        let mut buf = BUF.borrow_mut();
        while !data_slice.is_empty() {
            let amount = cmp::min(data_slice.len(), cfg::PAGE_SIZE);
            mem.read_bytes(buf.as_mut_ptr(), amount, off)?;
            assert_eq!(buf[0..amount], data_slice[0..amount]);

            off += amount as goff;
            data_slice = &data_slice[amount..];
        }
    }

    Ok(())
}

pub fn load_program(
    act: &Activity,
    mapper: &mut dyn Mapper,
    file: &mut BufReader<FileRef<dyn File>>,
) -> Result<usize, Error> {
    let mut buf = vec![0u8; 4096];
    let hdr: elf::Ehdr = read_object(file)?;

    if hdr.ident[0] != b'\x7F'
        || hdr.ident[1] != b'E'
        || hdr.ident[2] != b'L'
        || hdr.ident[3] != b'F'
    {
        return Err(Error::new(Code::InvalidElf));
    }

    // copy load segments to destination tile
    let mut end = 0;
    let mut off = hdr.phoff;
    for _ in 0..hdr.phnum {
        // load program header
        file.seek(off, SeekMode::SET)?;
        let phdr: elf::Phdr = read_object(file)?;
        off += hdr.phentsize as usize;

        // we're only interested in non-empty load segments
        if phdr.ty != elf::PT::LOAD.val || phdr.memsz == 0 {
            continue;
        }

        load_segment(act, mapper, file, &phdr, &mut *buf)?;

        end = phdr.vaddr + phdr.memsz as usize;
    }

    // create area for stack
    let (stack_addr, stack_size) = act.tile_desc().stack_space();
    mapper.map_anon(
        act.pager(),
        stack_addr as goff,
        stack_size,
        kif::Perm::RW,
        MapFlags::PRIVATE | MapFlags::UNINIT,
    )?;

    // create heap
    let heap_begin = math::round_up(end, cfg::PAGE_SIZE);
    let (heap_size, flags) = if act.pager().is_some() {
        (cfg::APP_HEAP_SIZE, MapFlags::NOLPAGE)
    }
    else {
        (cfg::MOD_HEAP_SIZE, MapFlags::empty())
    };
    mapper.map_anon(
        act.pager(),
        heap_begin as goff,
        heap_size,
        kif::Perm::RW,
        MapFlags::PRIVATE | MapFlags::UNINIT | flags,
    )?;

    Ok(hdr.entry)
}

pub fn write_arguments<I, S>(mem: &MemGate, off: &mut usize, args: I) -> Result<usize, Error>
where
    I: iter::IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut argptr = Vec::<u64>::new();
    let mut argbuf = Vec::new();

    let mut argoff = *off;
    for s in args {
        // push argv entry
        argptr.push(argoff as u64);

        // push string
        let arg = s.as_ref().as_bytes();
        argbuf.extend_from_slice(arg);

        // 0-terminate it
        argbuf.push(b'\0');

        argoff += arg.len() + 1;
    }
    argptr.push(0);

    let env_page_off = (cfg::ENV_START & !cfg::PAGE_MASK) as goff;
    write_bytes_checked(
        mem,
        *off,
        argbuf.as_ptr() as *const _,
        argbuf.len(),
        *off as goff - env_page_off,
    )?;

    argoff = math::round_up(argoff, size_of::<u64>());
    write_bytes_checked(
        mem,
        argoff,
        argptr.as_ptr() as *const _,
        argptr.len() * size_of::<u64>(),
        argoff as goff - env_page_off,
    )?;

    *off = argoff + argptr.len() * size_of::<u64>();
    Ok(argoff as usize)
}

fn load_segment(
    act: &Activity,
    mapper: &mut dyn Mapper,
    file: &mut BufReader<FileRef<dyn File>>,
    phdr: &elf::Phdr,
    buf: &mut [u8],
) -> Result<(), Error> {
    let prot = kif::Perm::from(elf::PF::from_bits_truncate(phdr.flags));
    let size = math::round_up(phdr.memsz as usize, cfg::PAGE_SIZE);

    let needs_init = if phdr.memsz == phdr.filesz {
        mapper.map_file(
            act.pager(),
            file,
            phdr.offset as usize,
            phdr.vaddr as goff,
            size,
            prot,
            MapFlags::PRIVATE,
        )
    }
    else {
        assert!(phdr.filesz == 0);
        mapper.map_anon(
            act.pager(),
            phdr.vaddr as goff,
            size,
            prot,
            MapFlags::PRIVATE,
        )
    }?;

    if needs_init {
        let mem = act.get_mem(
            phdr.vaddr as goff,
            math::round_up(size, cfg::PAGE_SIZE) as goff,
            kif::Perm::RW,
        )?;
        init_mem(
            buf,
            &mem,
            file,
            phdr.vaddr as usize,
            phdr.offset as usize,
            phdr.filesz as usize,
            phdr.memsz as usize,
        )
    }
    else {
        Ok(())
    }
}

fn init_mem(
    buf: &mut [u8],
    mem: &MemGate,
    file: &mut BufReader<FileRef<dyn File>>,
    vaddr: usize,
    foff: usize,
    fsize: usize,
    memsize: usize,
) -> Result<(), Error> {
    file.seek(foff, SeekMode::SET)?;

    let mut count = fsize;
    let mut segoff = 0;
    while count > 0 {
        let amount = cmp::min(count, buf.len());
        let amount = file.read(&mut buf[0..amount])?;

        write_bytes_checked(
            mem,
            vaddr + segoff as usize,
            buf.as_mut_ptr(),
            amount,
            segoff,
        )?;

        count -= amount;
        segoff += amount as goff;
    }

    clear_mem(buf, mem, vaddr, segoff as usize, (memsize - fsize) as usize)
}

fn clear_mem(
    buf: &mut [u8],
    mem: &MemGate,
    virt: usize,
    mut off: usize,
    mut len: usize,
) -> Result<(), Error> {
    if len == 0 {
        return Ok(());
    }

    for it in buf.iter_mut() {
        *it = 0;
    }

    while len > 0 {
        let amount = cmp::min(len, buf.len());
        write_bytes_checked(mem, virt, buf.as_mut_ptr(), amount, off as goff)?;
        len -= amount;
        off += amount;
    }

    Ok(())
}
