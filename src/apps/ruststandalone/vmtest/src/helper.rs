/*
 * Copyright (C) 2021-2022 Nils Asmussen, Barkhausen Institut
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

use core::mem;
use core::ptr;

use base::cell::{LazyStaticRefCell, StaticCell};
use base::cfg;
use base::env;
use base::io::{self, LogFlags};
use base::kif::{PageFlags, Perm};
use base::libc;
use base::log;
use base::machine;
use base::mem::{PhysAddr, PhysAddrRaw, VirtAddr};
use base::tcu::{EpId, Message, Reg, EP_REGS, TCU};

use crate::paging;

use isr::{ISRArch, ISR};

static STATE: LazyStaticRefCell<isr::State> = LazyStaticRefCell::default();
pub static XLATES: StaticCell<u64> = StaticCell::new(0);

const HEAP_SIZE: usize = 64 * 1024;

// the heap area needs to be page-byte aligned
#[repr(align(4096))]
struct Heap([u64; HEAP_SIZE / mem::size_of::<u64>()]);
#[used]
static mut HEAP: Heap = Heap([0; HEAP_SIZE / mem::size_of::<u64>()]);

extern "C" {
    fn __m3_init_libc(argc: i32, argv: *const *const u8, envp: *const *const u8, tls: bool);
    fn __m3_heap_set_area(begin: usize, end: usize);
}

#[no_mangle]
pub extern "C" fn abort() {
    exit(1);
}

#[no_mangle]
pub extern "C" fn exit(_code: i32) {
    machine::write_coverage(0);
    machine::shutdown();
}

pub extern "C" fn tmcall(state: &mut isr::State) -> *mut libc::c_void {
    let virt = VirtAddr::from(state.r[isr::TMC_ARG1]);
    let access = Perm::from_bits_truncate(state.r[isr::TMC_ARG2] as u32);
    let access = PageFlags::from(access) & PageFlags::RW;

    log!(
        LogFlags::Debug,
        "tmcall::transl_fault(virt={}, access={:?})",
        virt,
        access
    );

    XLATES.set(XLATES.get() + 1);

    let (phys, flags) = paging::translate(virt, access);
    // no page faults supported
    assert!(!(flags & PageFlags::RW) & access == PageFlags::empty());
    log!(
        LogFlags::Debug,
        "TCU can continue with phys={} flags={:?}",
        phys,
        flags
    );

    // insert TLB entry
    TCU::insert_tlb(crate::OWN_ACT, virt, phys, flags).unwrap();

    state as *mut _ as *mut libc::c_void
}

pub fn init(name: &str) {
    unsafe {
        __m3_init_libc(0, ptr::null(), ptr::null(), false);
        __m3_heap_set_area(
            &HEAP.0 as *const u64 as usize,
            &HEAP.0 as *const u64 as usize + HEAP.0.len() * 8,
        );
    }

    io::init(env::boot().tile_id(), name);

    if !env::boot().tile_desc().has_virtmem() {
        use ::paging::ArchPaging;
        log!(LogFlags::Info, "Disabling paging...");
        ::paging::Paging::disable();
    }
    else {
        log!(LogFlags::Info, "Setting up paging...");
        paging::init();
    }

    log!(LogFlags::Info, "Setting up interrupts...");
    STATE.set(isr::State::default());
    ISR::init(&mut STATE.borrow_mut());
    ISR::reg_tm_calls(tmcall);
    ISR::enable_irqs();

    if env::boot().tile_desc().has_virtmem() {
        // now that we're running with virtual memory enabled and can handle interrupts, we want to know about PMP failures
        TCU::enable_pmp_cureqs();
    }
}

pub fn virt_to_phys(virt: VirtAddr) -> (VirtAddr, PhysAddr) {
    let tile_desc = env::boot().tile_desc();
    if !tile_desc.has_virtmem() {
        (virt, virt.as_phys(tile_desc))
    }
    else {
        let (phys, _flags) = paging::translate(virt, PageFlags::R);
        (
            virt,
            PhysAddr::new_raw(
                tile_desc,
                phys.as_raw() + (virt.as_local() & cfg::PAGE_MASK) as PhysAddrRaw,
            ),
        )
    }
}

pub fn fetch_msg(ep: EpId, rbuf: VirtAddr) -> Option<&'static Message> {
    TCU::fetch_msg(ep).map(|off| TCU::offset_to_msg(rbuf, off))
}

pub fn config_local_ep<CFG>(ep: EpId, cfg: CFG)
where
    CFG: FnOnce(&mut [Reg]),
{
    let mut regs = [0; EP_REGS];
    cfg(&mut regs);
    TCU::set_ep_regs(ep, &regs);
}
