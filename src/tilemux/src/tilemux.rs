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
mod cureq;
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
use base::io::{self, LogFlags};
use base::kif;
use base::libc;
use base::log;
use base::machine;
use base::mem;
use base::tcu;

use core::ptr;

use isr::{ISRArch, ISR};

extern "C" {
    fn __m3_init_libc(argc: i32, argv: *const *const u8, envp: *const *const u8, tls: bool);
    fn __m3_heap_set_area(begin: usize, end: usize);
}

const HEAP_SIZE: usize = 512 * 1024;

// the heap area needs to be page-byte aligned
#[repr(align(4096))]
struct Heap([u64; HEAP_SIZE / mem::size_of::<u64>()]);
#[used]
static mut HEAP: Heap = Heap([0; HEAP_SIZE / mem::size_of::<u64>()]);

pub struct TMEnv {
    tile_id: u64,
    tile_desc: kif::TileDesc,
    platform: env::Platform,
}

static TM_ENV: StaticRefCell<TMEnv> = StaticRefCell::new(TMEnv {
    tile_id: 0,
    tile_desc: kif::TileDesc::new_from(0),
    platform: env::Platform::Gem5,
});

pub fn pex_env() -> Ref<'static, TMEnv> {
    TM_ENV.borrow()
}

pub fn app_env() -> &'static mut env::BaseEnv {
    unsafe { &mut *(cfg::ENV_START.as_mut_ptr()) }
}

pub struct PagefaultMessage {
    pub op: u64,
    pub virt: mem::VirtAddr,
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
        activities::schedule(action).as_mut_ptr()
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
    log!(
        LogFlags::Error,
        "Unexpected IRQ with user state:\n{:?}",
        state
    );
    activities::remove_cur(Code::Unspecified);

    leave(state)
}

#[cfg(any(
    target_arch = "riscv64",
    target_arch = "riscv32",
    target_arch = "x86_64"
))]
pub extern "C" fn fpu_ex(state: &mut arch::State) -> *mut libc::c_void {
    arch::handle_fpu_ex(state);
    leave(state)
}

pub extern "C" fn mmu_pf(state: &mut arch::State) -> *mut libc::c_void {
    let (virt, perm) = ISR::get_pf_info(state);
    if vma::handle_pf(state, virt, perm).is_err() {
        activities::remove_cur(Code::Unspecified);
    }

    leave(state)
}

pub extern "C" fn tmcall(state: &mut arch::State) -> *mut libc::c_void {
    tmcalls::handle_call(state);

    leave(state)
}

pub extern "C" fn ext_irq(state: &mut arch::State) -> *mut libc::c_void {
    match ISR::fetch_irq() {
        isr::IRQSource::TCU(tcu::IRQ::Timer) => {
            activities::cur().consume_time();
            timer::trigger();
        },

        isr::IRQSource::TCU(tcu::IRQ::CUReq) => {
            if let Some(r) = tcu::TCU::get_cu_req() {
                log!(LogFlags::MuxCUReqs, "Got {:x?}", r);
                cureq::handle(r);
            }
        },

        isr::IRQSource::Ext(id) => {
            irqs::signal(id);
        },
    }

    leave(state)
}

#[no_mangle]
pub extern "C" fn init() -> usize {
    // init our own environment; at this point we can still access app_env, because it is mapped by
    // the gem5 loader for us. afterwards, our address space does not contain that anymore.
    {
        let mut env = TM_ENV.borrow_mut();
        env.tile_id = app_env().boot.tile_id;
        env.tile_desc = kif::TileDesc::new_from(app_env().boot.tile_desc);
        env.platform = app_env().boot.platform;
    }

    unsafe {
        __m3_init_libc(0, ptr::null(), ptr::null(), false);
        __m3_heap_set_area(
            &HEAP.0 as *const u64 as usize,
            &HEAP.0 as *const u64 as usize + HEAP.0.len() * mem::size_of::<u64>(),
        );
    }

    io::init(
        tcu::TileId::new_from_raw(pex_env().tile_id as u16),
        "tilemux",
    );
    activities::init();

    // switch to idle; we don't want to keep the reference here, because activities::schedule()
    // below will also take a reference to idle.
    activities::idle().start();

    let state_top = {
        let mut idle = activities::idle();
        let state = idle.user_state();
        ISR::init(state);
        state as *const _ as usize + mem::size_of::<arch::State>()
    };

    isr::reg_all(unexpected_irq);
    ISR::reg_tm_calls(tmcall);
    ISR::reg_page_faults(mmu_pf);
    #[cfg(any(
        target_arch = "riscv64",
        target_arch = "riscv32",
        target_arch = "x86_64"
    ))]
    ISR::reg_illegal_instr(fpu_ex);
    ISR::reg_cu_reqs(ext_irq);
    ISR::reg_timer(ext_irq);
    ISR::reg_external(ext_irq);

    if TM_ENV.borrow().tile_desc.has_virtmem() {
        // Now that we're running with virtual memory enabled and can handle interrupts, we want to
        // know about PMP failures. Without virtual memory, the core might send speculative memory
        // accesses to physical memory and PMP is the first layer that can check their validity.
        // Therefore, PMP shouldn't report failures due to speculative accesses via CU requests.
        // With virtual memory, the core checks the validity of the accesses via paging and of
        // course still knows that these are speculative and can thus simply be ignored. The TCU
        // performing PMP however does not have this information.
        tcu::TCU::enable_pmp_cureqs();
    }

    // store platform already in app env, because we need it for logging
    app_env().boot.platform = pex_env().platform;

    // now that interrupts have been set up, we can schedule and thereby switch to idle in the TCU
    activities::schedule(activities::ScheduleAction::Yield);

    // in case messages arrived before we scheduled, handle them now. if any arrives after we
    // switched to idle, we'll get an interrupt later
    sidecalls::check();

    state_top
}
