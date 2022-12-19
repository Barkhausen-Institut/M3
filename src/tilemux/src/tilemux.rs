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

#![no_std]

#[allow(unused_extern_crates)]
extern crate heap;

mod activities;
mod arch;
mod corereq;
mod helper;
mod irqs;
mod quota;
mod sendqueue;
mod sidecalls;
mod timer;
mod tmcalls;
mod vma;

use base::cell::{Ref, StaticCell, StaticRefCell};
use base::cfg;
use base::env;
use base::errors::Code;
use base::io;
use base::kif;
use base::libc;
use base::log;
use base::machine;
use base::mem;
use base::tcu;

use core::ptr;

/// Logs errors
pub const LOG_ERR: bool = true;
/// Logs basic activity operations
pub const LOG_ACTS: bool = false;
/// Logs tmcalls
pub const LOG_CALLS: bool = false;
/// Logs context switches
pub const LOG_CTXSWS: bool = false;
/// Logs sidecalls
pub const LOG_SIDECALLS: bool = false;
/// Logs foreign messages
pub const LOG_FOREIGN_MSG: bool = false;
/// Logs core requests
pub const LOG_CORE_REQS: bool = false;
/// Logs page table allocations/frees
pub const LOG_PTS: bool = false;
/// Logs timer IRQs
pub const LOG_TIMER: bool = false;
/// Logs interrupts
pub const LOG_IRQS: bool = false;
/// Logs sendqueue operations
pub const LOG_SQUEUE: bool = false;
/// Logs quota operations
pub const LOG_QUOTAS: bool = false;

extern "C" {
    fn __m3_init_libc(argc: i32, argv: *const *const u8, envp: *const *const u8);
    fn __m3_heap_set_area(begin: usize, end: usize);
}

// the heap area needs to be page-byte aligned
#[repr(align(4096))]
struct Heap([u64; 512 * 1024]);
#[used]
static mut HEAP: Heap = Heap([0; 512 * 1024]);

pub struct TMEnv {
    tile_id: u64,
    tile_desc: kif::TileDesc,
    platform: u64,
}

static TM_ENV: StaticRefCell<TMEnv> = StaticRefCell::new(TMEnv {
    tile_id: 0,
    tile_desc: kif::TileDesc::new_from(0),
    platform: 0,
});

pub fn pex_env() -> Ref<'static, TMEnv> {
    TM_ENV.borrow()
}

pub fn app_env() -> &'static mut env::EnvData {
    unsafe { &mut *(cfg::ENV_START as *mut _) }
}

pub struct PagefaultMessage {
    pub op: u64,
    pub virt: u64,
    pub access: u64,
}

#[no_mangle]
pub extern "C" fn abort() {
    exit(1);
}

#[no_mangle]
pub extern "C" fn exit(_code: i32) {
    machine::shutdown();
}

static NEED_SCHED: StaticCell<Option<activities::ScheduleAction>> = StaticCell::new(None);
static NEED_TIMER: StaticCell<bool> = StaticCell::new(false);

#[inline]
fn leave(state: &mut arch::State) -> *mut libc::c_void {
    sidecalls::check();

    let addr = if let Some(action) = NEED_SCHED.replace(None) {
        activities::schedule(action) as *mut libc::c_void
    }
    else {
        state as *mut _ as *mut libc::c_void
    };

    if NEED_TIMER.replace(false) {
        timer::reprogram();
    }

    addr
}

pub fn reg_scheduling(action: activities::ScheduleAction) {
    NEED_SCHED.set(Some(action));
}

pub fn scheduling_pending() -> bool {
    NEED_SCHED.get().is_some()
}

pub fn reg_timer_reprogram() {
    NEED_TIMER.set(true);
}

pub extern "C" fn unexpected_irq(state: &mut arch::State) -> *mut libc::c_void {
    log!(LOG_ERR, "Unexpected IRQ with user state:\n{:?}", state);
    activities::remove_cur(Code::Unspecified);

    leave(state)
}

#[cfg(any(target_arch = "riscv64", target_arch = "x86_64"))]
pub extern "C" fn fpu_ex(state: &mut arch::State) -> *mut libc::c_void {
    arch::handle_fpu_ex(state);
    leave(state)
}

pub extern "C" fn mmu_pf(state: &mut arch::State) -> *mut libc::c_void {
    if arch::handle_mmu_pf(state).is_err() {
        activities::remove_cur(Code::Unspecified);
    }

    leave(state)
}

pub extern "C" fn tmcall(state: &mut arch::State) -> *mut libc::c_void {
    tmcalls::handle_call(state);

    leave(state)
}

pub extern "C" fn ext_irq(state: &mut arch::State) -> *mut libc::c_void {
    match isr::get_irq() {
        isr::IRQSource::TCU(tcu::IRQ::TIMER) => {
            activities::cur().consume_time();
            timer::trigger();
        },

        isr::IRQSource::TCU(tcu::IRQ::CORE_REQ) => {
            if let Some(r) = tcu::TCU::get_core_req() {
                log!(crate::LOG_CORE_REQS, "Got {:x?}", r);
                corereq::handle_recv(r);
            }
        },

        isr::IRQSource::Ext(id) => {
            irqs::signal(id);
        },

        n => log!(crate::LOG_ERR, "Unexpected IRQ {:?}", n),
    }

    leave(state)
}

#[no_mangle]
pub extern "C" fn init() -> usize {
    // switch to a different activity during the init phase to ensure that we don't miss messages for us
    let old_id = tcu::TCU::xchg_activity(0).unwrap();
    assert!((old_id >> 16) == 0);

    // init our own environment; at this point we can still access app_env, because it is mapped by
    // the gem5 loader for us. afterwards, our address space does not contain that anymore.
    {
        let mut env = TM_ENV.borrow_mut();
        env.tile_id = app_env().tile_id;
        env.tile_desc = kif::TileDesc::new_from(app_env().tile_desc);
        env.platform = app_env().platform;
    }

    unsafe {
        __m3_init_libc(0, ptr::null(), ptr::null());
        __m3_heap_set_area(
            &HEAP.0 as *const u64 as usize,
            &HEAP.0 as *const u64 as usize + HEAP.0.len() * 8,
        );
    }

    // initialize the TCU to translate tile ids to NoC ids from now on. we do not need that to
    // configure EPs here, but to extract PMP EPs and translate the NoC id to a tile id.
    tcu::TCU::init_tileid_translation(
        &app_env().raw_tile_ids[0..app_env().raw_tile_count as usize],
        false,
    );

    io::init(
        tcu::TileId::new_from_raw(pex_env().tile_id as u16),
        "tilemux",
    );
    activities::init();

    // switch to idle; we don't want to keep the reference here, because activities::schedule()
    // below will also take a reference to idle.
    activities::idle().start();
    activities::schedule(activities::ScheduleAction::Yield);

    let mut idle = activities::idle();
    let state = idle.user_state();
    let state_top = state as *const _ as usize + mem::size_of::<arch::State>();
    arch::init(state);
    // store platform already in app env, because we need it for logging
    app_env().platform = pex_env().platform;

    state_top
}
