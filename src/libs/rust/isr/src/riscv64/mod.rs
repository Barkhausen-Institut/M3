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

use base::backtrace;
use base::env;
use base::kif::PageFlags;
use base::libc;
use base::mem::VirtAddr;
use base::tcu;
use base::{read_csr, set_csr_bits, write_csr};

use core::convert::TryFrom;
use core::fmt;

use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::IRQSource;
use crate::StateArch;

pub const ISR_COUNT: usize = 32;

pub const TMC_ARG0: usize = 9; // a0 = x10
pub const TMC_ARG1: usize = 10; // a1 = x11
pub const TMC_ARG2: usize = 11; // a2 = x12
pub const TMC_ARG3: usize = 12; // a3 = x13
pub const TMC_ARG4: usize = 13; // a4 = x14

#[derive(Default)]
// see comment in ARM code
#[repr(C, align(8))]
pub struct RISCV64State {
    // general purpose registers
    pub r: [usize; 31],
    pub cause: usize,
    pub epc: usize,
    pub status: usize,
}

impl crate::StateArch for RISCV64State {
    fn instr_pointer(&self) -> VirtAddr {
        VirtAddr::from(self.epc)
    }

    fn base_pointer(&self) -> VirtAddr {
        VirtAddr::from(self.r[7])
    }

    fn came_from_user(&self) -> bool {
        ((self.status >> 8) & 1) == 0
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[repr(usize)]
pub enum Vector {
    // exceptions
    InstrMisaligned,
    InstrAccFault,
    IllegalInstr,
    Breakpoint,
    LoadMisaligned,
    LoadAccFault,
    StoreMisaligned,
    StoreAccFault,
    EnvUCall,
    EnvSCall,
    EnvMCall       = 11,
    InstrPagefault,
    LoadPagefault,
    StorePagefault = 15,

    // interrupts
    UserSWIRQ,
    SuperSWIRQ,
    MachSWIRQ      = 19,
    UserTimerIRQ,
    SuperTimerIRQ,
    MachTimerIRQ   = 23,
    UserExtIRQ,
    SuperExtIRQ,
    MachExtIRQ     = 27,
}

impl fmt::Debug for RISCV64State {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let vec = if (self.cause & 0x8000_0000_0000_0000) != 0 {
            16 + (self.cause & 0xF)
        }
        else {
            self.cause & 0xF
        };

        writeln!(fmt, "  vec: {:#x} ({:?})", vec, Vector::try_from(vec))?;
        for (idx, r) in { self.r }.iter().enumerate() {
            writeln!(fmt, "  r[{:02}]:  {:#x}", idx + 1, r)?;
        }
        writeln!(fmt, "  cause:  {:#x}", { self.cause })?;
        writeln!(fmt, "  epc:    {:#x}", { self.epc })?;
        writeln!(fmt, "  status: {:#x}", { self.status })?;
        writeln!(fmt, "  stval:  {:#x}", read_csr!("stval"))?;

        writeln!(fmt, "\nUser backtrace:")?;
        let mut bt = [VirtAddr::default(); 16];
        let bt_len = backtrace::collect_for(self.base_pointer(), &mut bt);
        for addr in bt.iter().take(bt_len) {
            writeln!(fmt, "  {:#x}", addr.as_local())?;
        }
        Ok(())
    }
}

mod plic {
    pub const TCU_ID: u32 = 1;
    pub const TIMER_ID: u32 = 2;

    const MMIO_PRIORITY: *mut u32 = 0x0C00_0000 as *mut u32;
    const MMIO_ENABLE: *mut u32 = 0x0C00_2080 as *mut u32;
    const MMIO_THRESHOLD: *mut u32 = 0x0C20_1000 as *mut u32;
    const MMIO_CLAIM: *mut u32 = 0x0C20_1004 as *mut u32;

    pub fn get() -> u32 {
        unsafe { MMIO_CLAIM.read_volatile() }
    }

    pub fn ack(id: u32) {
        unsafe {
            MMIO_CLAIM.write_volatile(id);
        }
    }

    pub fn enable(id: u32) {
        enable_mask(1 << id);
    }

    pub fn enable_mask(mask: u32) {
        unsafe {
            let val = MMIO_ENABLE.read_volatile();
            MMIO_ENABLE.write_volatile(val | mask);
        }
    }

    pub fn disable_mask(mask: u32) {
        unsafe {
            let val = MMIO_ENABLE.read_volatile();
            MMIO_ENABLE.write_volatile(val & !mask);
        }
    }

    pub fn set_priority(id: u32, prio: u8) {
        unsafe {
            MMIO_PRIORITY
                .add(id as usize)
                .write_volatile(prio as u32 & 0x7);
        }
    }

    pub fn set_threshold(threshold: u8) {
        unsafe {
            MMIO_THRESHOLD.write_volatile(threshold as u32 & 0x7);
        }
    }
}

extern "C" {
    fn isr_setup(stack: usize);
}

#[no_mangle]
pub extern "C" fn isr_handler(state: &mut RISCV64State) -> *mut libc::c_void {
    let vec = if (state.cause & 0x8000_0000_0000_0000) != 0 {
        16 + (state.cause & 0xF)
    }
    else {
        state.cause & 0xF
    };

    // don't repeat the ECALL instruction
    if vec >= 8 && vec <= 10 {
        state.epc += 4;
    }

    crate::ISRS.borrow()[vec](state)
}

pub struct RISCV64ISR {}

impl crate::ISRArch for RISCV64ISR {
    type State = RISCV64State;

    fn init(state: &mut Self::State) {
        // configure PLIC
        plic::set_threshold(0);
        for id in &[plic::TCU_ID, plic::TIMER_ID] {
            plic::enable(*id);
            plic::set_priority(*id, 1);
        }

        // disable timer interrupt
        const CLINT_MSIP: *mut u64 = 0x0200_0000 as *mut u64;
        unsafe {
            CLINT_MSIP.write_volatile(0);
        }

        unsafe {
            let state_top = (state as *mut Self::State).offset(1) as usize;
            isr_setup(state_top)
        };
    }

    fn set_entry_sp(sp: VirtAddr) {
        write_csr!("sscratch", sp.as_local());
    }

    fn reg_tm_calls(handler: crate::IsrFunc) {
        crate::reg(Vector::EnvUCall.into(), handler);
        crate::reg(Vector::EnvSCall.into(), handler);
    }

    fn reg_page_faults(handler: crate::IsrFunc) {
        crate::reg(Vector::InstrPagefault.into(), handler);
        crate::reg(Vector::LoadPagefault.into(), handler);
        crate::reg(Vector::StorePagefault.into(), handler);
    }

    fn reg_cu_reqs(handler: crate::IsrFunc) {
        Self::reg_external(handler);
    }

    fn reg_illegal_instr(handler: crate::IsrFunc) {
        crate::reg(Vector::IllegalInstr.into(), handler);
    }

    fn reg_timer(handler: crate::IsrFunc) {
        crate::reg(Vector::SuperTimerIRQ.into(), handler);
    }

    fn reg_external(handler: crate::IsrFunc) {
        crate::reg(Vector::SuperExtIRQ.into(), handler);
        crate::reg(Vector::MachExtIRQ.into(), handler);
    }

    fn get_pf_info(state: &Self::State) -> (VirtAddr, PageFlags) {
        let virt = VirtAddr::from(read_csr!("stval"));

        let perm = match Vector::try_from(state.cause & 0x1F).unwrap() {
            Vector::InstrPagefault => PageFlags::R | PageFlags::X,
            Vector::LoadPagefault => PageFlags::R,
            Vector::StorePagefault => PageFlags::R | PageFlags::W,
            _ => unreachable!(),
        };
        (virt, perm)
    }

    fn init_tls(_addr: VirtAddr) {
        // unused
    }

    fn enable_irqs() {
        // set SIE to 1
        set_csr_bits!("sstatus", 1 << 1);
    }

    fn fetch_irq() -> IRQSource {
        let irq = plic::get();
        assert!(irq != 0);

        // TODO: temporary (add to spec and make gem5 behave the same)
        if env::boot().platform == env::Platform::Hw {
            let tcu_set_irq_addr = 0xF000_3030 as *mut u64;
            unsafe {
                tcu_set_irq_addr.add((irq - 1) as usize).write_volatile(0);
            }
        }
        else {
            let tcu_irq = tcu::TCU::get_irq().unwrap();
            tcu::TCU::clear_irq(tcu_irq);
        }
        plic::ack(irq);

        match irq {
            plic::TCU_ID => IRQSource::TCU(tcu::IRQ::CUReq),
            plic::TIMER_ID => IRQSource::TCU(tcu::IRQ::Timer),
            n => IRQSource::Ext(n),
        }
    }

    fn register_ext_irq(irq: u32) {
        plic::set_priority(irq, 1);
    }

    fn enable_ext_irqs(mask: u32) {
        plic::enable_mask(mask);
    }

    fn disable_ext_irqs(mask: u32) {
        plic::disable_mask(mask);
    }
}