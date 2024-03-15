/*
 * Copyright (C) 2020-2022 Nils Asmussen, Barkhausen Institut
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

use base::cell::StaticCell;
use base::errors::Code;
use base::io::LogFlags;
use base::kif::tilemux;
use base::libc;
use base::mem::MaybeUninit;
use base::{log, read_csr, write_csr};

use num_enum::{FromPrimitive, IntoPrimitive};

use crate::activities;

extern "C" {
    fn save_fpu(state: &mut FPUState);
    fn restore_fpu(state: &FPUState);
}

pub type State = isr::State;

#[repr(C, align(8))]
pub struct FPUState {
    r: [MaybeUninit<usize>; 32],
    fcsr: usize,
    init: bool,
}

impl Default for FPUState {
    fn default() -> Self {
        Self {
            // we init that lazy on the first use of the FPU
            r: unsafe { MaybeUninit::uninit().assume_init() },
            fcsr: 0,
            init: false,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive, FromPrimitive)]
#[repr(usize)]
enum FSMode {
    #[default]
    OFF     = 0,
    INITIAL = 1,
    CLEAN   = 2,
    DIRTY   = 3,
}

static FPU_OWNER: StaticCell<activities::Id> = StaticCell::new(tilemux::ACT_ID);

fn get_fpu_mode(status: usize) -> FSMode {
    FSMode::from((status >> 13) & 0x3)
}

fn set_fpu_mode(mut status: usize, mode: FSMode) -> usize {
    status &= !(0x3 << 13);
    status | (mode as usize) << 13
}

pub fn init_state(state: &mut State, entry: usize, sp: usize) {
    state.r[9] = 0xDEAD_BEEF; // a0; don't set the stackpointer in crt0
    state.epc = entry;
    state.r[1] = sp;
    state.status = read_csr!("sstatus");
    state.status &= !(1 << 8); // user mode
    state.status |= 1 << 5; // interrupts enabled
    state.status = set_fpu_mode(state.status, FSMode::OFF);
}

pub fn forget_fpu(act_id: activities::Id) {
    if FPU_OWNER.get() == act_id {
        FPU_OWNER.set(tilemux::ACT_ID);
    }
}

pub fn disable_fpu() {
    let mut cur = activities::cur();
    if cur.id() != FPU_OWNER.get() {
        cur.user_state().status = set_fpu_mode(cur.user_state().status, FSMode::OFF);
    }
}

pub fn handle_fpu_ex(state: &mut State) {
    let mut cur = activities::cur();

    // if the FPU is enabled and we receive an illegal instruction exception, kill activity
    if get_fpu_mode(state.status) != FSMode::OFF {
        log!(
            LogFlags::Error,
            "Illegal instruction with user state:\n{:?}",
            state
        );
        activities::remove_cur(Code::Unspecified);
        return;
    }

    // enable FPU
    state.status = set_fpu_mode(state.status, FSMode::CLEAN);

    let old_id = FPU_OWNER.get() & 0xFFFF;
    if old_id != cur.id() {
        // enable FPU so that we can save/restore the FPU registers
        write_csr!("sstatus", set_fpu_mode(read_csr!("sstatus"), FSMode::CLEAN));

        // need to save old state?
        if old_id != tilemux::ACT_ID {
            let mut old_act = activities::get_mut(old_id).unwrap();
            unsafe { save_fpu(old_act.fpu_state()) };
        }

        // restore new state
        let fpu_state = cur.fpu_state();
        if fpu_state.init {
            unsafe { restore_fpu(fpu_state) };
        }
        else {
            unsafe { libc::memset(fpu_state as *mut _ as *mut libc::c_void, 0, 8 * 33) };
            fpu_state.init = true;
        }

        // we are owner now
        FPU_OWNER.set(cur.id());
    }
}
