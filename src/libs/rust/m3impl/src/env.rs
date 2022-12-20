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

use crate::cap::Selector;
use crate::cfg;
use crate::col::Vec;
use crate::com::SendGate;
use crate::errors::Error;
use crate::kif::{self, TileDesc};
use crate::serialize::M3Deserializer;
use crate::session::{Pager, ResMng};
use crate::tcu;
use crate::util;
use crate::vfs::{FileTable, MountTable};

pub use base::env::*;

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct EnvData {
    base: base::env::EnvData,
}

impl EnvData {
    pub fn platform(&self) -> Platform {
        Platform::from(self.base.platform)
    }

    pub fn set_platform(&mut self, platform: Platform) {
        self.base.platform = platform.val;
    }

    pub fn tile_id(&self) -> u64 {
        self.base.tile_id
    }

    pub fn shared(&self) -> bool {
        self.base.shared != 0
    }

    pub fn tile_desc(&self) -> TileDesc {
        TileDesc::new_from(self.base.tile_desc)
    }

    pub fn set_pedesc(&mut self, tile: TileDesc) {
        self.base.tile_desc = tile.value();
    }

    pub fn set_argc(&mut self, argc: usize) {
        self.base.argc = argc as u64;
    }

    pub fn set_argv(&mut self, argv: usize) {
        self.base.argv = argv as u64;
    }

    pub fn set_envp(&mut self, envp: usize) {
        self.base.envp = envp as u64;
    }

    pub fn set_sp(&mut self, sp: usize) {
        self.base.sp = sp as u64;
    }

    pub fn set_entry(&mut self, entry: usize) {
        self.base.entry = entry as u64;
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
            s => Some(ResMng::new(SendGate::new_bind(s))),
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
        &self.base.raw_tile_ids[0..self.base.raw_tile_count as usize]
    }

    pub fn copy_tile_ids(&mut self, tile_ids: &[u64]) {
        self.base.raw_tile_count = tile_ids.len() as u64;
        self.base.raw_tile_ids[0..tile_ids.len()].copy_from_slice(tile_ids);
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

    pub fn set_closure(&mut self, addr: usize) {
        self.base.closure = addr as u64;
    }

    pub fn set_first_sel(&mut self, sel: Selector) {
        self.base.first_sel = sel;
    }

    pub fn set_rmng(&mut self, sel: Selector) {
        self.base.rmng_sel = sel;
    }

    pub fn set_files(&mut self, off: usize, len: usize) {
        self.base.fds_addr = off as u64;
        self.base.fds_len = len as u64;
    }

    pub fn set_mounts(&mut self, off: usize, len: usize) {
        self.base.mounts_addr = off as u64;
        self.base.mounts_len = len as u64;
    }

    pub fn set_data(&mut self, off: usize, len: usize) {
        self.base.data_addr = off as u64;
        self.base.data_len = len as u64;
    }

    pub fn set_pager(&mut self, pager: &Pager) {
        self.base.pager_sess = pager.sel();
        self.base.pager_sgate = pager.sgate_sel();
    }
}

pub fn get() -> &'static EnvData {
    // safety: we trust our loader
    unsafe { &*(cfg::ENV_START as *const _) }
}
