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

use crate::cfg;

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct EnvData {
    // boot env
    pub platform: u64,
    pub tile_id: u64,
    pub tile_desc: u64,
    pub argc: u64,
    pub argv: u64,
    pub heap_size: u64,
    pub kenv: u64,
    pub closure: u64,

    // set by TileMux
    pub shared: u64,

    // m3 env
    pub envp: u64,
    pub sp: u64,
    pub entry: u64,
    pub first_std_ep: u64,
    pub first_sel: u64,
    pub act_id: u64,

    pub rmng_sel: u64,
    pub pager_sess: u64,
    pub pager_sgate: u64,

    pub mounts_addr: u64,
    pub mounts_len: u64,

    pub fds_addr: u64,
    pub fds_len: u64,

    pub data_addr: u64,
    pub data_len: u64,

    // only used in C++
    pub _backend: u64,
}

pub fn get() -> &'static EnvData {
    // safety: the cast is okay because we trust our loader to put the environment at that place
    unsafe { &*(cfg::ENV_START as *const _) }
}
