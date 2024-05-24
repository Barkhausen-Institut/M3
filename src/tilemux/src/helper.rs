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

use base::cpu::{CPUOps, CPU};
use base::machine;
use base::mem::VirtAddr;
use base::tcu;

pub fn flush_cache() {
    // nothing to do if we don't have virtual memory
    if !crate::pex_env().tile_desc.has_virtmem() {
        return;
    }

    // safety: cfg::TILE_MEM_BASE is mapped and sufficiently large
    unsafe { machine::flush_cache() };
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
        self.cmd_regs[1] = tcu::TCU::read_unpriv_reg(tcu::UnprivReg::Arg1);
        let (addr, size) = tcu::TCU::read_data();
        self.cmd_regs[2] = addr as tcu::Reg;
        self.cmd_regs[3] = size as tcu::Reg;
    }

    pub fn restore(&mut self) {
        tcu::TCU::write_unpriv_reg(tcu::UnprivReg::Arg1, self.cmd_regs[1]);
        tcu::TCU::write_data(
            VirtAddr::from(self.cmd_regs[2] as usize),
            self.cmd_regs[3] as usize,
        );
        // always restore the command register, because the previous activity might have an error code
        // in the command register or similar.
        CPU::memory_barrier();
        tcu::TCU::write_unpriv_reg(tcu::UnprivReg::Command, self.cmd_regs[0]);
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

