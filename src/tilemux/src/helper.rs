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

use base::cfg;
use base::tcu;
use core::sync::atomic;

pub fn flush_cache() {
    // nothing to do if we don't have virtual memory
    if !crate::pex_env().tile_desc.has_virtmem() {
        return;
    }

    #[cfg(target_vendor = "hw")]
    let (cacheline_size, cache_size) = (64, 512 * 1024);
    #[cfg(target_vendor = "gem5")]
    let (cacheline_size, cache_size) = (64, (32 + 256) * 1024);

    // ensure that we replace all cachelines in cache
    let mut addr = cfg::TILE_MEM_BASE as *const u64;
    unsafe {
        let end = addr.add(cache_size / 8);
        while addr < end {
            let _val = addr.read_volatile();
            addr = addr.add(cacheline_size / 8);
        }
    }

    #[cfg(target_vendor = "hw")]
    unsafe {
        core::arch::asm!("fence.i");
    }
}

pub struct TCUCmdState {
    cmd_regs: [tcu::Reg; 4],
}

impl TCUCmdState {
    pub const fn new() -> Self {
        TCUCmdState { cmd_regs: [0; 4] }
    }

    pub fn save(&mut self) {
        // abort the current command, if there is any
        let old_cmd = tcu::TCU::abort_cmd().unwrap();

        self.cmd_regs[0] = old_cmd;
        self.cmd_regs[1] = tcu::TCU::read_unpriv_reg(tcu::UnprivReg::ARG1);
        self.cmd_regs[2] = tcu::TCU::read_unpriv_reg(tcu::UnprivReg::DATA_ADDR);
        self.cmd_regs[3] = tcu::TCU::read_unpriv_reg(tcu::UnprivReg::DATA_SIZE);
    }

    pub fn restore(&mut self) {
        tcu::TCU::write_unpriv_reg(tcu::UnprivReg::ARG1, self.cmd_regs[1]);
        tcu::TCU::write_unpriv_reg(tcu::UnprivReg::DATA_ADDR, self.cmd_regs[2]);
        tcu::TCU::write_unpriv_reg(tcu::UnprivReg::DATA_SIZE, self.cmd_regs[3]);
        // always restore the command register, because the previous activity might have an error code
        // in the command register or similar.
        atomic::fence(atomic::Ordering::SeqCst);
        tcu::TCU::write_unpriv_reg(tcu::UnprivReg::COMMAND, self.cmd_regs[0]);
    }
}

pub struct TCUGuard {
    cmd: TCUCmdState,
}

impl TCUGuard {
    pub fn new() -> Self {
        let mut cmd = TCUCmdState::new();
        cmd.save();
        TCUGuard { cmd }
    }
}

impl Drop for TCUGuard {
    fn drop(&mut self) {
        self.cmd.restore();
    }
}
