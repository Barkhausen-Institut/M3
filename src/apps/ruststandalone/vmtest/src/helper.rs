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

use base::cell::{LazyStaticRefCell, StaticCell};
use base::cfg;
use base::env;
use base::io;
use base::kif::{PageFlags, Perm, TileDesc};
use base::libc;
use base::log;
use base::machine;
use base::tcu::{EpId, Message, Reg, TileId, EP_REGS, TCU};

use crate::paging;

static STATE: LazyStaticRefCell<isr::State> = LazyStaticRefCell::default();
pub static XLATES: StaticCell<u64> = StaticCell::new(0);

#[no_mangle]
pub extern "C" fn abort() {
    exit(1);
}

#[no_mangle]
pub extern "C" fn exit(_code: i32) {
    machine::shutdown();
}

pub extern "C" fn tmcall(state: &mut isr::State) -> *mut libc::c_void {
    let virt = state.r[isr::TMC_ARG1];
    let access = Perm::from_bits_truncate(state.r[isr::TMC_ARG2] as u32);
    let flags = PageFlags::from(access) & PageFlags::RW;

    log!(
        crate::LOG_TMCALLS,
        "tmcall::transl_fault(virt={:#x}, access={:?})",
        virt,
        access
    );

    XLATES.set(XLATES.get() + 1);

    let pte = paging::translate(virt, flags);
    // no page faults supported
    assert!(!(pte & PageFlags::RW.bits()) & flags.bits() == 0);
    log!(crate::LOG_TMCALLS, "TCU can continue with PTE={:#x}", pte);

    // insert TLB entry
    let phys = pte & !(cfg::PAGE_MASK as u64);
    let flags = PageFlags::from_bits_truncate(pte & cfg::PAGE_MASK as u64);
    TCU::insert_tlb(crate::OWN_ACT, virt, phys, flags).unwrap();

    state as *mut _ as *mut libc::c_void
}

pub fn init(name: &str) {
    io::init(TileId::new_from_raw(env::data().tile_id as u16), name);

    if !TileDesc::new_from(env::data().tile_desc).has_virtmem() {
        log!(crate::LOG_DEF, "Disabling paging...");
        ::paging::disable_paging();
    }
    else {
        log!(crate::LOG_DEF, "Setting up paging...");
        paging::init();
    }

    log!(crate::LOG_DEF, "Setting up interrupts...");
    STATE.set(isr::State::default());
    isr::init(&mut STATE.borrow_mut());
    isr::init_tmcalls(tmcall);
    isr::enable_irqs();
}

pub fn virt_to_phys(virt: usize) -> (usize, ::paging::Phys) {
    if !TileDesc::new_from(env::data().tile_desc).has_virtmem() {
        (virt, virt as u64)
    }
    else {
        let rbuf_pte = paging::translate(virt, PageFlags::R);
        (
            virt,
            (rbuf_pte & !cfg::PAGE_MASK as u64) + (virt & cfg::PAGE_MASK) as u64,
        )
    }
}

pub fn fetch_msg(ep: EpId, rbuf: usize) -> Option<&'static Message> {
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
