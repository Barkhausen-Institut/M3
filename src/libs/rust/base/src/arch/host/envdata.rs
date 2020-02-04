/*
 * Copyright (C) 2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
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

use cell::StaticCell;
use cfg;
use core::ptr;
use kif::{CapSel, PEDesc};

pub struct EnvData {
    pub pe_id: u32,
    pub shared: u32,
    pub pe_desc: u32,
    pub argc: u32,
    pub argv: u64,
    pub first_sel: u32,
    pub kmem_sel: u32,
}

impl EnvData {
    pub fn new(
        pe_id: u32,
        pe_desc: PEDesc,
        argc: i32,
        argv: *const *const i8,
        first_sel: CapSel,
        kmem_sel: CapSel,
    ) -> Self {
        EnvData {
            pe_id,
            shared: 0,
            pe_desc: pe_desc.value(),
            argc: argc as u32,
            argv: argv as u64,
            first_sel: first_sel as u32,
            kmem_sel: kmem_sel as u32,
        }
    }
}

static ENV_DATA: StaticCell<Option<EnvData>> = StaticCell::new(None);
static MEM: StaticCell<Option<usize>> = StaticCell::new(None);

pub fn get() -> &'static mut EnvData {
    ENV_DATA.get_mut().as_mut().unwrap()
}

pub fn set(data: EnvData) {
    ENV_DATA.set(Some(data));
}

pub fn eps_start() -> usize {
    mem_start()
}

pub fn rbuf_start() -> usize {
    mem_start() + cfg::EPMEM_SIZE
}

pub fn heap_start() -> usize {
    mem_start() + cfg::EPMEM_SIZE + cfg::RECVBUF_SIZE
}

pub fn mem_start() -> usize {
    match MEM.get() {
        None => {
            let addr = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    cfg::LOCAL_MEM_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANON | libc::MAP_PRIVATE,
                    -1,
                    0,
                )
            };
            assert!(addr != libc::MAP_FAILED);
            MEM.set(Some(addr as usize));
            addr as usize
        },
        Some(m) => *m,
    }
}
