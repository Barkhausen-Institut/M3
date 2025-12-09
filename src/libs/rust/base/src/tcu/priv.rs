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

//! The TCU's privileged interface

use num_enum::{IntoPrimitive, TryFromPrimitive};

use bitflags::bitflags;

use crate::arch::{CPUOps, CPU};
use crate::cfg;
use crate::errors::{Code, Error};
use crate::kif::PageFlags;
use crate::mem::{self, PhysAddr, PhysAddrRaw, VirtAddr};

use crate::tcu::unpriv::UnprivReg;
use crate::tcu::{EpId, Reg, MMIO_ADDR, MMIO_PRIV_ADDR, TCU};

/// The privileged commands
#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive)]
#[repr(u64)]
pub enum PrivCmdOpCode {
    /// The idle command has no effect
    Idle,
    /// Invalidate a single TLB entry
    InvPage,
    /// Invalidate all TLB entries
    InvTLB,
    /// Insert an entry into the TLB
    InsTLB,
    /// Changes the activity
    XchgAct,
    /// Sets the timer
    SetTimer,
    /// Abort the current command
    AbortCmd,
    /// Fetches and acknowledges the most recent IRQ
    FetchIRQ,
}

pub const CU_REQ_TYPE_MASK: Reg = 0x7;

#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive)]
#[repr(u64)]
/// The privileged registers
pub enum PrivReg {
    /// For CU requests
    CUReq,
    /// Controls the privileged interface
    PrivCtrl,
    /// For privileged commands
    PrivCmd,
    /// The argument for privileged commands
    PrivCmdArg,
    /// The current activity
    CurAct,
}

/// The TCU-internal IRQ ids to clear IRQs
#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[repr(u64)]
pub enum IRQ {
    /// The CU request IRQ
    CUReq,
    /// The timer IRQ
    Timer,
}

/// The different CU requests that are sent by the TCU to the CU.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CUReq {
    /// A foreign-msg CU request, that is sent by the TCU if a message was received for another
    /// activity
    ForeignReceive { act: u16, ep: EpId },

    /// A physical-memory protection faliure that is sent by the TCU if a PMP access failed (e.g.,
    /// due to missing permissions)
    PMPFailure { phys: u32, write: bool, error: Code },
}

impl CUReq {
    pub fn new_foreign_receive(req: Reg) -> Self {
        Self::ForeignReceive {
            act: (req >> 48) as u16,
            ep: ((req >> 3) & 0xFFFF) as EpId,
        }
    }

    pub fn new_pmp_failure(req: Reg) -> Self {
        Self::PMPFailure {
            phys: (req >> 32) as u32,
            write: ((req >> 3) & 0x1) != 0,
            error: Code::try_from(((req >> 4) & 0x1ffff) as u32).unwrap(),
        }
    }
}

bitflags! {
    pub struct PrivCtrl : Reg {
        /// If enabled, the TCU reports PMP failures as CU requests
        const PMP_FAILURES = 0x1;
    }
}

impl TCU {
    /// Fetches and thereby acknowledges the currently handled IRQ.
    ///
    /// This notifies the TCU that the next IRQ can be triggered, if any.
    pub fn fetch_irq() -> Result<IRQ, Error> {
        Self::write_priv_reg(
            PrivReg::PrivCmd,
            Self::build_priv_cmd(PrivCmdOpCode::FetchIRQ, 0),
        );
        Self::get_priv_error()?;
        IRQ::try_from(Self::read_priv_reg(PrivReg::PrivCmdArg))
            .map_err(|_| Error::new(Code::InvArgs))
    }

    /// Returns the current CU request
    pub fn get_cu_req() -> Option<CUReq> {
        let req = Self::read_priv_reg(PrivReg::CUReq);
        match req & CU_REQ_TYPE_MASK {
            0x2 => Some(CUReq::new_foreign_receive(req)),
            0x3 => Some(CUReq::new_pmp_failure(req)),
            _ => None,
        }
    }

    /// Provides the TCU with the response to a CU request
    pub fn set_cu_resp() {
        Self::write_priv_reg(PrivReg::CUReq, 0x1)
    }

    /// Enables CU requests in case of PMP failures
    pub fn enable_pmp_cureqs() {
        Self::write_priv_reg(PrivReg::PrivCtrl, PrivCtrl::PMP_FAILURES.bits());
    }

    /// Returns the current activity with its id and message count
    pub fn get_cur_activity() -> Reg {
        Self::read_priv_reg(PrivReg::CurAct)
    }

    /// Aborts the current command or activity, specified in `req`, and returns the command register to
    /// use for a retry later.
    pub fn abort_cmd() -> Result<Reg, Error> {
        // save the old value before aborting
        let cmd_reg = Self::read_unpriv_reg(UnprivReg::Command);
        // ensure that we read the command register before the abort has been executed
        CPU::memory_barrier();
        Self::write_priv_reg(
            PrivReg::PrivCmd,
            Self::build_priv_cmd(PrivCmdOpCode::AbortCmd, 0),
        );

        loop {
            let (cmd, err, arg) = Self::decode_priv_cmd(Self::read_priv_reg(PrivReg::PrivCmd));
            if cmd == PrivCmdOpCode::Idle.into() {
                if err != Code::Success {
                    break Err(Error::new(err));
                }
                else if arg == 0 {
                    // if the command was finished successfully, use the current command register
                    // to ensure that we don't forget the error code
                    break Ok(Self::read_unpriv_reg(UnprivReg::Command));
                }
                else {
                    // otherwise use the old one to repeat it later
                    break Ok(cmd_reg);
                };
            }
        }
    }

    /// Switches to the given activity and returns the old activity
    pub fn xchg_activity(nact: Reg) -> Result<Reg, Error> {
        Self::write_priv_reg(
            PrivReg::PrivCmd,
            Self::build_priv_cmd(PrivCmdOpCode::XchgAct, nact),
        );
        Self::get_priv_error()?;
        Ok(Self::read_priv_reg(PrivReg::PrivCmdArg))
    }

    /// Invalidates the TCU's TLB
    pub fn invalidate_tlb() {
        Self::write_priv_reg(
            PrivReg::PrivCmd,
            Self::build_priv_cmd(PrivCmdOpCode::InvTLB, 0),
        );
        Self::wait_priv_cmd();
    }

    /// Invalidates the entry with given address space id and virtual address in the TCU's TLB
    pub fn invalidate_page(asid: u16, virt: VirtAddr) -> Result<(), Error> {
        Self::invalidate_page_unchecked(asid, virt);
        Self::get_priv_error()
    }

    /// Invalidates the entry with given address space id and virtual address in the TCU's TLB
    ///
    /// In contrast to `invalidate_page`, errors are ignored. Note that we avoid even allocating the
    /// Error type here, because that causes a heap allocation in debug mode and is used in the
    /// paging code.
    pub fn invalidate_page_unchecked(asid: u16, virt: VirtAddr) {
        Self::write_priv_reg(PrivReg::PrivCmdArg, virt.as_local() as Reg);
        let val = Self::build_priv_cmd(PrivCmdOpCode::InvPage, asid as Reg);
        Self::write_priv_reg(PrivReg::PrivCmd, val);
        Self::wait_priv_cmd();
    }

    /// Inserts the given entry into the TCU's TLB
    pub fn insert_tlb(
        asid: u16,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: PageFlags,
    ) -> Result<(), Error> {
        let mut tlb_flags = 0 as Reg;
        if flags.contains(PageFlags::R) {
            tlb_flags |= 1;
        }
        if flags.contains(PageFlags::W) {
            tlb_flags |= 2;
        }
        if flags.contains(PageFlags::FIXED) {
            tlb_flags |= 4;
        }

        let phys = if flags.contains(PageFlags::L) {
            // the current TCU's TLB does not support large pages
            phys.as_raw() | (virt.as_local() & cfg::LPAGE_MASK & !cfg::PAGE_MASK) as PhysAddrRaw
        }
        else {
            phys.as_raw()
        };

        let (arg_addr, cmd_addr) = (virt.as_local(), phys as usize);

        Self::write_priv_reg(PrivReg::PrivCmdArg, arg_addr as Reg);
        CPU::memory_barrier();
        let cmd = Self::build_priv_cmd(
            PrivCmdOpCode::InsTLB,
            ((asid as Reg) << 32) | ((cmd_addr as Reg) & !(cfg::PAGE_MASK as Reg)) | tlb_flags,
        );
        Self::write_priv_reg(PrivReg::PrivCmd, cmd);
        Self::get_priv_error()
    }

    /// Sets the timer to fire in `delay_ns` nanoseconds if `delay_ns` is nonzero. Otherwise, unsets
    /// the timer.
    pub fn set_timer(delay_ns: u64) -> Result<(), Error> {
        let delay = match env!("M3_TARGET") {
            "hw" => delay_ns / 10,
            _ => delay_ns,
        };
        Self::write_priv_reg(
            PrivReg::PrivCmd,
            Self::build_priv_cmd(PrivCmdOpCode::SetTimer, delay),
        );
        Self::get_priv_error()
    }

    /// Waits until the current command is completed and returns the error, if any occurred
    #[inline(always)]
    fn get_priv_error() -> Result<(), Error> {
        Result::from(Self::wait_priv_cmd())
    }

    /// Waits until the current command is completed and returns the error, if any occurred
    #[inline(always)]
    fn wait_priv_cmd() -> Code {
        loop {
            let (op, err, _arg) = Self::decode_priv_cmd(Self::read_priv_reg(PrivReg::PrivCmd));
            if op == PrivCmdOpCode::Idle.into() {
                return err;
            }
        }
    }

    fn build_priv_cmd(op: PrivCmdOpCode, arg: Reg) -> Reg {
        let mut cmd: Reg = op.into();
        if cfg!(M3_TARGET = "gem5") || cfg!(M3_TARGET = "hw") {
            cmd |= arg << 10;
        }
        else {
            cmd |= arg << 9;
        }
        cmd
    }

    fn decode_priv_cmd(cmd: Reg) -> (Reg, Code, Reg) {
        let op = cmd & 0xF;
        let (err, arg) = if cfg!(M3_TARGET = "gem5") || cfg!(M3_TARGET = "hw") {
            ((cmd >> 4) & 0x3F, cmd >> 10)
        }
        else {
            ((cmd >> 4) & 0x1F, cmd >> 9)
        };
        let code = Code::try_from(err as u32).unwrap();
        (op, code, arg)
    }

    fn read_priv_reg(reg: PrivReg) -> Reg {
        Self::read_reg(
            ((MMIO_PRIV_ADDR.as_local() - MMIO_ADDR.as_local()) / mem::size_of::<Reg>())
                + reg as usize,
        )
    }

    fn write_priv_reg(reg: PrivReg, val: Reg) {
        Self::write_reg(
            ((MMIO_PRIV_ADDR.as_local() - MMIO_ADDR.as_local()) / mem::size_of::<Reg>())
                + reg as usize,
            val,
        )
    }
}
