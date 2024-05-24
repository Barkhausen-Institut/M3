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
use core::intrinsics;
use core::ptr;

use crate::cap::Selector;
use crate::cfg;
use crate::client::{Pager, ResMng};
use crate::col::Vec;
use crate::com::{MemGate, SendGate};
use crate::errors::Error;
use crate::kif::{self, TileDesc};
use crate::mem::{self, GlobOff, VirtAddr};
use crate::serialize::M3Deserializer;
use crate::tcu;
use crate::tiles::OwnActivity;
use crate::util;
use crate::vfs::{FileTable, MountTable};

pub use base::env::*;

/// Writes the given arguments to `mem` at given address
///
/// This is intended [`ChildActivity`](`crate::tiles::ChildActivity`) and other components that want
/// to start applications and therefore need to pass arguments and environment variables to the
/// application.
///
/// Returns the address of arguments array (argv)
pub fn write_args<S>(
    args: &[S],
    mem: &MemGate,
    addr: &mut VirtAddr,
    env_off: GlobOff,
) -> Result<VirtAddr, Error>
where
    S: AsRef<str>,
{
    let (arg_buf, arg_ptr, arg_end) = collect_args(args, *addr);

    // write actual arguments to memory
    mem.write_bytes(
        arg_buf.as_ptr() as *const _,
        arg_buf.len(),
        (*addr).as_goff() - env_off,
    )?;

    // write argument pointers to memory
    let arg_ptr_addr = util::math::round_up(arg_end, VirtAddr::from(mem::size_of::<VirtAddr>()));
    mem.write_bytes(
        arg_ptr.as_ptr() as *const _,
        arg_ptr.len() * mem::size_of::<VirtAddr>(),
        arg_ptr_addr.as_goff() - env_off,
    )?;

    *addr = arg_ptr_addr + arg_ptr.len() * mem::size_of::<VirtAddr>();
    Ok(arg_ptr_addr)
}

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct Env {
    base: base::env::BaseEnv,
}

impl Env {
    pub fn platform(&self) -> Platform {
        self.base.boot.platform
    }

    pub fn set_platform(&mut self, platform: Platform) {
        self.base.boot.platform = platform;
    }

    pub fn tile_id(&self) -> tcu::TileId {
        self.base.boot.tile_id()
    }

    pub fn shared(&self) -> bool {
        self.base.shared != 0
    }

    pub fn tile_desc(&self) -> TileDesc {
        TileDesc::new_from(self.base.boot.tile_desc)
    }

    pub fn set_pedesc(&mut self, tile: TileDesc) {
        self.base.boot.tile_desc = tile.value();
    }

    pub fn set_argc(&mut self, argc: usize) {
        self.base.boot.argc = argc as u64;
    }

    pub fn set_argv(&mut self, argv: VirtAddr) {
        self.base.boot.argv = argv.as_raw();
    }

    pub fn set_envp(&mut self, envp: VirtAddr) {
        self.base.boot.envp = envp.as_raw();
    }

    pub fn set_sp(&mut self, sp: VirtAddr) {
        self.base.sp = sp.as_raw();
    }

    pub fn set_entry(&mut self, entry: VirtAddr) {
        self.base.entry = entry.as_raw();
    }

    pub fn set_heap_size(&mut self, size: usize) {
        self.base.heap_size = size as u64;
    }

    pub fn first_std_ep(&self) -> tcu::EpId {
        self.base.first_std_ep as tcu::EpId
    }

    pub fn set_first_std_ep(&mut self, start: tcu::EpId) {
        self.base.first_std_ep = start as u64;
    }

    pub fn activity_id(&self) -> tcu::ActId {
        self.base.act_id as tcu::ActId
    }

    pub fn set_activity_id(&mut self, id: tcu::ActId) {
        self.base.act_id = id as u64;
    }

    pub fn load_pager(&self) -> Option<Pager> {
        match self.base.pager_sess {
            0 => None,
            s => Some(Pager::new_bind(s as Selector, self.base.pager_sgate)),
        }
    }

    pub fn load_rmng(&self) -> Option<ResMng> {
        match self.base.rmng_sel as Selector {
            kif::INVALID_SEL => None,
            s => Some(ResMng::new(SendGate::new_bind(s).unwrap())),
        }
    }

    pub fn load_first_sel(&self) -> Selector {
        // it's initially 0. make sure it's at least the first usable selector
        cmp::max(kif::FIRST_FREE_SEL, self.base.first_sel as Selector)
    }

    pub fn load_mounts(&self) -> MountTable {
        if self.base.mounts_len != 0 {
            // safety: we trust our loader
            let slice = unsafe {
                util::slice_for(
                    self.base.mounts_addr as *const u64,
                    self.base.mounts_len as usize,
                )
            };
            MountTable::unserialize(&mut M3Deserializer::new(slice))
        }
        else {
            MountTable::default()
        }
    }

    pub fn load_fds(&self) -> FileTable {
        if self.base.fds_len != 0 {
            // safety: we trust our loader
            let slice = unsafe {
                util::slice_for(self.base.fds_addr as *const u64, self.base.fds_len as usize)
            };
            FileTable::unserialize(&mut M3Deserializer::new(slice))
        }
        else {
            FileTable::default()
        }
    }

    pub fn load_data(&self) -> Vec<u64> {
        if self.base.data_len != 0 {
            // safety: we trust our loader
            let slice = unsafe {
                util::slice_for(
                    self.base.data_addr as *const u64,
                    self.base.data_len as usize,
                )
            };
            slice.to_vec()
        }
        else {
            Vec::default()
        }
    }

    pub fn tile_ids(&self) -> &[u64] {
        &self.base.boot.raw_tile_ids[0..self.base.boot.raw_tile_count as usize]
    }

    pub fn copy_tile_ids(&mut self, tile_ids: &[u64]) {
        self.base.boot.raw_tile_count = tile_ids.len() as u64;
        self.base.boot.raw_tile_ids[0..tile_ids.len()].copy_from_slice(tile_ids);
    }

    // --- gem5 specific API ---

    pub fn load_closure(&self) -> Option<fn() -> Result<(), Error>> {
        if self.base.closure != 0 {
            // safety: we trust our loader
            unsafe {
                Some(intrinsics::transmute(
                    self.base.closure as *mut u8 as *mut _,
                ))
            }
        }
        else {
            None
        }
    }

    pub fn set_closure(&mut self, addr: VirtAddr) {
        self.base.closure = addr.as_raw();
    }

    pub fn set_first_sel(&mut self, sel: Selector) {
        self.base.first_sel = sel;
    }

    pub fn set_rmng(&mut self, sel: Selector) {
        self.base.rmng_sel = sel;
    }

    pub fn set_files(&mut self, addr: VirtAddr, len: usize) {
        self.base.fds_addr = addr.as_raw();
        self.base.fds_len = len as u64;
    }

    pub fn set_mounts(&mut self, addr: VirtAddr, len: usize) {
        self.base.mounts_addr = addr.as_raw();
        self.base.mounts_len = len as u64;
    }

    pub fn set_data(&mut self, addr: VirtAddr, len: usize) {
        self.base.data_addr = addr.as_raw();
        self.base.data_len = len as u64;
    }

    pub fn set_pager(&mut self, pager: &Pager) {
        self.base.pager_sess = pager.sess_sel();
        self.base.pager_sgate = pager.sgate_sel();
    }
}

pub fn get() -> &'static Env {
    // safety: we trust our loader
    unsafe { &*(cfg::ENV_START.as_ptr()) }
}

extern "C" {
    fn __m3_init_libc(argc: i32, argv: *const *const u8, envp: *const *const u8, tls: bool);
}

extern "Rust" {
    fn main() -> Result<(), Error>;
}

pub fn init() {
    #[cfg(feature = "linux")]
    crate::linux::init();
    crate::cap::init();
    crate::syscalls::init();
    crate::com::pre_init();
    crate::tiles::init();
    crate::io::init();
    crate::com::init();

    #[cfg(feature = "linux")]
    if let Some(cl) = crate::env::get().load_closure() {
        OwnActivity::exit(cl());
    }
}

pub fn deinit() {
    crate::io::deinit();
    crate::vfs::deinit();
}

#[no_mangle]
pub extern "C" fn env_run() {
    unsafe {
        __m3_init_libc(0, ptr::null(), ptr::null(), false);
    }
    init();

    let res = if let Some(cl) = crate::env::get().load_closure() {
        cl()
    }
    else {
        unsafe { main() }
    };

    OwnActivity::exit(res);
}
