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

use core::cmp;
use core::mem::size_of_val;

use crate::boxed::Box;
use crate::cfg;
use crate::client::MapFlags;
use crate::com::MemGate;
use crate::elf;
use crate::errors::Error;
use crate::io::{read_object, Read};
use crate::kif;
use crate::mem::{GlobOff, VirtAddr};
use crate::tiles::{Activity, Mapper};
use crate::util::math;
use crate::vec;
use crate::vfs::{BufReader, File, FileRef, Seek, SeekMode};

pub(crate) fn load_program(
    act: &Activity,
    mapper: &mut dyn Mapper,
    file: &mut BufReader<FileRef<dyn File>>,
) -> Result<VirtAddr, Error> {
    let mut buf = vec![0u8; 4096];
    let hdr: elf::ElfHeaderCommon = read_object(file)?;
    hdr.ident.check_magic()?;

    file.seek(0, SeekMode::Set)?;
    let hdr = hdr.load_hdr(file)?;

    let heap_begin = load_segments(act, mapper, file, &hdr, &mut buf)?;
    create_heap(act, mapper, heap_begin)?;
    create_stack(act, mapper)?;

    Ok(VirtAddr::from(hdr.entry()))
}

fn create_stack(act: &Activity, mapper: &mut dyn Mapper) -> Result<(), Error> {
    let (stack_addr, stack_size) = act.tile_desc().stack_space();
    mapper
        .map_anon(
            act.pager(),
            stack_addr,
            stack_size,
            kif::Perm::RW,
            MapFlags::PRIVATE | MapFlags::UNINIT,
        )
        .map(|_| ())
}

fn create_heap(act: &Activity, mapper: &mut dyn Mapper, start: VirtAddr) -> Result<(), Error> {
    let (heap_size, flags) = if act.pager().is_some() {
        (cfg::APP_HEAP_SIZE, MapFlags::NOLPAGE)
    }
    else {
        (cfg::MOD_HEAP_SIZE, MapFlags::empty())
    };
    mapper
        .map_anon(
            act.pager(),
            start,
            heap_size,
            kif::Perm::RW,
            MapFlags::PRIVATE | MapFlags::UNINIT | flags,
        )
        .map(|_| ())
}

fn load_segments(
    act: &Activity,
    mapper: &mut dyn Mapper,
    file: &mut BufReader<FileRef<dyn File>>,
    hdr: &Box<dyn elf::ElfHeader>,
    buf: &mut [u8],
) -> Result<VirtAddr, Error> {
    let mut end = 0;
    let mut off = hdr.ph_off();
    for _ in 0..hdr.ph_num() {
        // load program header
        file.seek(off, SeekMode::Set)?;
        let phdr = hdr.load_ph(file)?;
        off += size_of_val(&*phdr);

        // we're only interested in non-empty load segments
        if phdr.ty() != elf::PHType::Load.into() || phdr.mem_size() == 0 {
            continue;
        }

        load_segment(act, mapper, file, &phdr, buf)?;

        end = phdr.virt_addr() + phdr.mem_size();
    }

    Ok(VirtAddr::from(math::round_up(end, cfg::PAGE_SIZE)))
}

fn load_segment(
    act: &Activity,
    mapper: &mut dyn Mapper,
    file: &mut BufReader<FileRef<dyn File>>,
    phdr: &Box<dyn elf::ProgramHeader>,
    buf: &mut [u8],
) -> Result<(), Error> {
    let prot = kif::Perm::from(elf::PHFlags::from_bits_truncate(phdr.flags()));
    let size = math::round_up(phdr.mem_size(), cfg::PAGE_SIZE);

    let needs_init = if phdr.mem_size() == phdr.file_size() {
        mapper.map_file(
            act.pager(),
            file,
            phdr.offset(),
            VirtAddr::from(phdr.virt_addr()),
            size,
            prot,
            MapFlags::PRIVATE,
        )
    }
    else {
        assert!(phdr.file_size() == 0);
        mapper.map_anon(
            act.pager(),
            VirtAddr::from(phdr.virt_addr()),
            size,
            prot,
            MapFlags::PRIVATE,
        )
    }?;

    if needs_init {
        let mem = act.get_mem(
            VirtAddr::from(phdr.virt_addr()),
            math::round_up(size, cfg::PAGE_SIZE) as GlobOff,
            kif::Perm::RW,
        )?;
        init_mem(
            buf,
            &mem,
            file,
            phdr.offset(),
            phdr.file_size(),
            phdr.mem_size(),
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
    offset: usize,
    file_size: usize,
    mem_size: usize,
) -> Result<(), Error> {
    let mut segoff = 0;
    if file_size > 0 {
        file.seek(offset, SeekMode::Set)?;

        let mut count = file_size;
        while count > 0 {
            let amount = cmp::min(count, buf.len());
            let amount = file.read(&mut buf[0..amount])?;

            mem.write_bytes(buf.as_mut_ptr(), amount, segoff)?;

            count -= amount;
            segoff += amount as GlobOff;
        }
    }

    clear_mem(buf, mem, segoff as usize, mem_size - file_size)
}

fn clear_mem(buf: &mut [u8], mem: &MemGate, mut off: usize, mut len: usize) -> Result<(), Error> {
    if len == 0 {
        return Ok(());
    }

    for it in buf.iter_mut() {
        *it = 0;
    }

    while len > 0 {
        let amount = cmp::min(len, buf.len());
        mem.write_bytes(buf.as_mut_ptr(), amount, off as GlobOff)?;
        len -= amount;
        off += amount;
    }

    Ok(())
}
