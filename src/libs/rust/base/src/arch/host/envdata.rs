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

use core::ptr;

use crate::cell::{LazyReadOnlyCell, StaticCell};
use crate::cfg;
use crate::kif::{CapSel, TileDesc, TileDescRaw};
use crate::util;

pub struct EnvData {
    pub tile_id: u64,
    pub shared: u32,
    pub tile_desc: TileDescRaw,
    pub argc: u32,
    pub argv: u64,
    pub envp: u64,
    pub first_sel: u32,
    pub kmem_sel: u32,
    pub platform: u64,
}

impl EnvData {
    pub fn new(
        tile_id: u64,
        tile_desc: TileDesc,
        argc: i32,
        argv: *const *const i8,
        first_sel: CapSel,
        kmem_sel: CapSel,
    ) -> Self {
        EnvData {
            tile_id,
            shared: 0,
            tile_desc: tile_desc.value(),
            argc: argc as u32,
            argv: argv as u64,
            envp: 0, // not supported on host
            first_sel: first_sel as u32,
            kmem_sel: kmem_sel as u32,
            platform: crate::envdata::Platform::HOST.val,
        }
    }
}

static ENV_DATA: LazyReadOnlyCell<EnvData> = LazyReadOnlyCell::default();
static MEM: StaticCell<Option<usize>> = StaticCell::new(None);

pub fn get() -> &'static EnvData {
    ENV_DATA.get()
}

pub fn set(data: EnvData) {
    ENV_DATA.set(data);
}

pub fn tmp_dir() -> &'static str {
    get_env("M3_HOST_TMP\0")
}

pub fn out_dir() -> &'static str {
    get_env("M3_OUT\0")
}

fn get_env(name: &str) -> &'static str {
    unsafe {
        let value = libc::getenv(name.as_bytes().as_ptr() as *const i8);
        assert!(!value.is_null());
        util::cstr_to_str(value)
    }
}

pub fn eps_start() -> usize {
    mem_start()
}

pub fn rbuf_start() -> usize {
    mem_start() + cfg::EPMEM_SIZE
}

pub fn heap_start() -> usize {
    mem_start() + cfg::EPMEM_SIZE + cfg::RBUF_SIZE
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
        Some(m) => m,
    }
}
