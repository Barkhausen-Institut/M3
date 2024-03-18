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

#![no_std]

#[allow(unused_extern_crates)]
extern crate lang;

use core::fmt::Debug;

use cfg_if::cfg_if;

use base::cell::StaticRefCell;
use base::kif::PageFlags;
use base::mem::VirtAddr;
use base::tcu;
use base::tmif;

pub trait StateArch {
    fn instr_pointer(&self) -> VirtAddr;
    fn base_pointer(&self) -> VirtAddr;
    fn came_from_user(&self) -> bool;
}

pub trait ISRArch {
    type State: StateArch + Debug;

    fn init(state: &mut Self::State);
    fn set_entry_sp(sp: VirtAddr);

    fn reg_tm_calls(handler: crate::IsrFunc);
    fn reg_page_faults(handle: crate::IsrFunc);
    fn reg_cu_reqs(handler: crate::IsrFunc);
    fn reg_illegal_instr(handler: crate::IsrFunc);
    fn reg_timer(handler: crate::IsrFunc);
    fn reg_external(handler: crate::IsrFunc);

    fn get_pf_info(state: &Self::State) -> (VirtAddr, PageFlags);

    fn init_tls(addr: VirtAddr);

    fn enable_irqs();
    fn fetch_irq() -> IRQSource;
    fn register_ext_irq(irq: u32);
    fn enable_ext_irqs(mask: u32);
    fn disable_ext_irqs(mask: u32);
}

cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        #[path = "x86_64/mod.rs"]
        mod isa;
        pub use isa::{Segment, DPL};
        pub type ISR = isa::X86ISR;
    }
    else if #[cfg(target_arch = "arm")] {
        #[path = "arm/mod.rs"]
        mod isa;
        pub type ISR = isa::ARMISR;
    }
    else {
        #[path = "riscv/mod.rs"]
        mod isa;
        pub type ISR = isa::RISCVISR;
    }
}

pub use isa::{TMC_ARG0, TMC_ARG1, TMC_ARG2, TMC_ARG3, TMC_ARG4};

pub type State = <ISR as ISRArch>::State;
pub type IsrFunc = extern "C" fn(state: &mut State) -> *mut base::libc::c_void;

static ISRS: StaticRefCell<[IsrFunc; isa::ISR_COUNT]> =
    StaticRefCell::new([unexpected_irq; isa::ISR_COUNT]);

#[derive(Debug)]
pub enum IRQSource {
    TCU(tcu::IRQ),
    Ext(tmif::IRQId),
}

pub extern "C" fn unexpected_irq(state: &mut State) -> *mut base::libc::c_void {
    panic!("Unexpected IRQ with user state:\n{:?}", state);
}

pub fn reg_all(handler: crate::IsrFunc) {
    for i in 0..isa::ISR_COUNT {
        reg(i, handler);
    }
}

fn reg(idx: usize, func: IsrFunc) {
    ISRS.borrow_mut()[idx] = func;
}
