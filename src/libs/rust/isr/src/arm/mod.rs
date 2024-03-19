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

use base::backtrace;
use base::kif::PageFlags;
use base::libc;
use base::mem::VirtAddr;
use base::tcu;

use core::arch::asm;
use core::convert::TryFrom;
use core::fmt;

use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::IRQSource;
use crate::StateArch;

pub const ISR_COUNT: usize = 8;

pub const TMC_ARG0: usize = 0; // r0
pub const TMC_ARG1: usize = 1; // r1
pub const TMC_ARG2: usize = 2; // r2
pub const TMC_ARG3: usize = 3; // r3
pub const TMC_ARG4: usize = 4; // r4

#[derive(Default)]
// for some reason, we need to specify the alignment here. actually, this struct needs to be packed,
// but unfortunately, we cannot specify both packed and align. but without packed seems to be fine,
// because there are no holes between the fields.
#[repr(C, align(4))]
pub struct ARMState {
    pub sp: usize,
    pub lr: usize,
    pub vec: usize,
    pub r: [usize; 13], // r0 .. r12
    pub klr: usize,
    pub pc: usize,
    pub cpsr: usize,
}

impl crate::StateArch for ARMState {
    fn instr_pointer(&self) -> VirtAddr {
        VirtAddr::from(self.pc)
    }

    fn base_pointer(&self) -> VirtAddr {
        VirtAddr::from(self.r[11])
    }

    fn came_from_user(&self) -> bool {
        (self.cpsr & 0x0F) == 0x0
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[repr(usize)]
pub enum Vector {
    Reset,
    UndefInstr,
    SWI,
    PrefetchAbort,
    DataAbort,
    _Reserved,
    IRQ,
    FIQ,
}

impl fmt::Debug for ARMState {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(fmt, "  lr:     {:#x}", { self.lr })?;
        writeln!(fmt, "  sp:     {:#x}", { self.sp })?;
        writeln!(
            fmt,
            "  vec:    {:#x} ({:?})",
            { self.vec },
            Vector::try_from(self.vec)
        )?;
        writeln!(fmt, "  klr:    {:#x}", { self.klr })?;
        for (idx, r) in { self.r }.iter().enumerate() {
            writeln!(fmt, "  r[{:02}]:  {:#x}", idx, r)?;
        }
        writeln!(fmt, "  pc:     {:#x}", { self.pc })?;
        writeln!(fmt, "  cpsr:   {:#x}", { self.cpsr })?;

        writeln!(fmt, "\nUser backtrace:")?;
        let mut bt = [VirtAddr::default(); 16];
        let bt_len = backtrace::collect_for(self.base_pointer(), &mut bt);
        for addr in bt.iter().take(bt_len) {
            writeln!(fmt, "  {:#x}", addr.as_local())?;
        }
        Ok(())
    }
}

#[no_mangle]
pub extern "C" fn isr_handler(state: &mut ARMState) -> *mut libc::c_void {
    // repeat last instruction
    if state.vec == 4 {
        state.pc -= 8;
    }
    // repeat last instruction, except for SWIs
    else if state.vec != 2 {
        state.pc -= 4;
    }

    crate::ISRS.borrow()[state.vec](state)
}

pub struct ARMISR {}

impl crate::ISRArch for ARMISR {
    type State = ARMState;

    fn init(_state: &mut Self::State) {
        // nothing to do
    }

    fn set_entry_sp(_sp: VirtAddr) {
        // nothing to do
    }

    fn reg_tm_calls(handler: crate::IsrFunc) {
        crate::reg(Vector::SWI.into(), handler);
    }

    fn reg_page_faults(handler: crate::IsrFunc) {
        crate::reg(Vector::PrefetchAbort.into(), handler);
        crate::reg(Vector::DataAbort.into(), handler);
    }

    fn reg_cu_reqs(handler: crate::IsrFunc) {
        crate::reg(Vector::IRQ.into(), handler);
    }

    fn reg_illegal_instr(_handler: crate::IsrFunc) {
        unimplemented!()
    }

    fn reg_timer(handler: crate::IsrFunc) {
        crate::reg(Vector::IRQ.into(), handler);
    }

    fn reg_external(_handler: crate::IsrFunc) {
    }

    fn get_pf_info(state: &Self::State) -> (VirtAddr, PageFlags) {
        let (virt, perm) = if state.vec == Vector::DataAbort.into() {
            let dfar: usize;
            let dfsr: usize;
            unsafe {
                asm!(
                    "mrc p15, 0, {0}, c6, c0, 0",
                    "mrc p15, 0, {1}, c5, c0, 0",
                    out(reg) dfar,
                    out(reg) dfsr,
                    options(nostack, nomem),
                );
            }
            (
                dfar,
                if dfsr & 0x800 != 0 {
                    PageFlags::RW
                }
                else {
                    PageFlags::R
                },
            )
        }
        else {
            let ifar: usize;
            unsafe {
                asm!(
                    "mrc p15, 0, {0}, c6, c0, 2",
                    out(reg) ifar,
                    options(nostack, nomem),
                );
            }
            (ifar, PageFlags::RX)
        };
        (VirtAddr::from(virt), perm)
    }

    fn init_tls(_addr: VirtAddr) {
        // unused
    }

    fn enable_irqs() {
        unsafe { asm!("msr cpsr, 0x53") };
    }

    fn fetch_irq() -> IRQSource {
        let irq = tcu::TCU::fetch_irq().unwrap();
        IRQSource::TCU(irq)
    }

    fn register_ext_irq(_irq: u32) {
    }

    fn enable_ext_irqs(_mask: u32) {
    }

    fn disable_ext_irqs(_mask: u32) {
    }
}
