/*
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

use core::any::Any;
use core::cmp;
use core::fmt;

use m3::cap::Selector;
use m3::cell::RefCell;
use m3::cfg::PAGE_BITS;
use m3::col::Vec;
use m3::com::MemGate;
use m3::errors::{Code, Error};
use m3::goff;
use m3::io::{Read, Write};
use m3::kif::Perm;
use m3::rc::Rc;
use m3::session::{HashInput, HashOutput, MapFlags, Pager};
use m3::syscalls;
use m3::tiles::Mapper;
use m3::vfs;

use crate::memory;

pub struct BootFile {
    mgate: MemGate,
    size: usize,
    pos: usize,
}

impl BootFile {
    pub fn new(mgate: MemGate, size: usize) -> Self {
        BootFile {
            mgate,
            size,
            pos: 0,
        }
    }
}

impl vfs::File for BootFile {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    // not needed here
    fn fd(&self) -> vfs::Fd {
        0
    }

    fn set_fd(&mut self, _fd: vfs::Fd) {
    }

    fn stat(&self) -> Result<vfs::FileInfo, Error> {
        Ok(vfs::FileInfo {
            mode: vfs::FileMode::FILE_DEF,
            size: self.size as usize,
            extents: 1,
            ..Default::default()
        })
    }

    fn file_type(&self) -> u8 {
        b'F'
    }
}

impl vfs::Seek for BootFile {
    fn seek(&mut self, off: usize, whence: vfs::SeekMode) -> Result<usize, Error> {
        match whence {
            vfs::SeekMode::CUR => self.pos += off,
            vfs::SeekMode::SET => self.pos = off,
            vfs::SeekMode::END => self.pos = self.size,
            _ => panic!("Unexpected whence"),
        }
        Ok(self.pos)
    }
}

impl Read for BootFile {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if self.pos >= self.size {
            Ok(0)
        }
        else {
            let amount = cmp::min(buf.len(), self.size - self.pos);
            self.mgate.read(&mut buf[0..amount], self.pos as goff)?;
            self.pos += amount;
            Ok(amount)
        }
    }
}

impl Write for BootFile {
    fn write(&mut self, _buf: &[u8]) -> Result<usize, Error> {
        Err(Error::new(Code::NotSup))
    }
}

impl vfs::Map for BootFile {
    fn map(
        &self,
        _pager: &Pager,
        _virt: goff,
        _off: usize,
        _len: usize,
        _prot: Perm,
        _flags: MapFlags,
    ) -> Result<(), Error> {
        // not used
        Ok(())
    }
}

impl HashInput for BootFile {
}
impl HashOutput for BootFile {
}

impl fmt::Debug for BootFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BootFile[sel={}, size={:#x}, pos={:#x}]",
            self.mgate.sel(),
            self.size,
            self.pos
        )
    }
}

pub struct BootMapper {
    act_sel: Selector,
    mem_sel: Selector,
    has_virtmem: bool,
    mem_pool: Rc<RefCell<memory::MemPool>>,
    allocs: Vec<memory::Allocation>,
}

impl BootMapper {
    pub fn new(
        act_sel: Selector,
        mem_sel: Selector,
        has_virtmem: bool,
        mem_pool: Rc<RefCell<memory::MemPool>>,
    ) -> Self {
        BootMapper {
            act_sel,
            mem_sel,
            has_virtmem,
            mem_pool,
            allocs: Vec::new(),
        }
    }

    pub fn fetch_allocs(self) -> Vec<memory::Allocation> {
        self.allocs
    }
}

impl Mapper for BootMapper {
    fn map_file(
        &mut self,
        pager: Option<&Pager>,
        _file: &mut vfs::BufReader<vfs::FileRef<dyn vfs::File>>,
        foff: usize,
        virt: goff,
        len: usize,
        perm: Perm,
        flags: MapFlags,
    ) -> Result<bool, Error> {
        if perm.contains(Perm::W) {
            // create new memory and copy data into it
            self.map_anon(pager, virt, len, perm, flags)
        }
        else if self.has_virtmem {
            // map the memory of the boot module directly; therefore no initialization necessary
            syscalls::create_map(
                (virt >> PAGE_BITS) as Selector,
                self.act_sel,
                self.mem_sel,
                (foff >> PAGE_BITS) as Selector,
                len >> PAGE_BITS,
                perm,
            )
            .map(|_| false)
        }
        else {
            Ok(true)
        }
    }

    fn map_anon(
        &mut self,
        _pager: Option<&Pager>,
        virt: goff,
        len: usize,
        perm: Perm,
        _flags: MapFlags,
    ) -> Result<bool, Error> {
        if self.has_virtmem {
            let alloc = self.mem_pool.borrow_mut().allocate(len as goff)?;
            let msel = self.mem_pool.borrow().mem_cap(alloc.slice_id());

            syscalls::create_map(
                (virt >> PAGE_BITS) as Selector,
                self.act_sel,
                msel,
                (alloc.addr() >> PAGE_BITS) as Selector,
                len >> PAGE_BITS,
                perm,
            )?;
            self.allocs.push(alloc);
            Ok(true)
        }
        else {
            // nothing to do
            Ok(true)
        }
    }
}
