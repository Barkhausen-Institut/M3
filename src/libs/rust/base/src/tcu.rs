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

//! The Trusted Communication Unit interface

use bitflags::bitflags;
use cfg_if::cfg_if;
use core::cmp;
use core::fmt;
use core::intrinsics;
use core::slice;
use core::sync::atomic;

use crate::arch;
use crate::cell::LazyReadOnlyCell;
use crate::cfg;
use crate::col::Vec;
use crate::errors::{Code, Error};
use crate::goff;
use crate::io::log::TCU;
use crate::kif::{PageFlags, Perm};
use crate::mem;
use crate::serialize::{Deserialize, Serialize};
use crate::tmif;
use crate::util::math;

/// A TCU register
pub type Reg = u64;
/// An endpoint id
pub type EpId = u16;
/// A TCU label used in send EPs
pub type Label = u32;
/// A activity id
pub type ActId = u16;

/// A tile id, consisting of a chip and chip-local tile id
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TileId {
    id: u16,
}

impl TileId {
    /// Constructs a new tile id out of the given chip and chip-local tile id
    pub const fn new(chip: u8, tile: u8) -> Self {
        Self {
            id: (chip as u16) << 8 | tile as u16,
        }
    }

    /// Constructs a new tile id from the given raw id (e.g., as stored in TCUs)
    pub const fn new_from_raw(raw: u16) -> Self {
        Self { id: raw }
    }

    /// Returns the chip id
    pub const fn chip(&self) -> u8 {
        (self.id >> 8) as u8
    }

    /// Returns the chip-local tile id
    pub const fn tile(&self) -> u8 {
        (self.id & 0xFF) as u8
    }

    /// Returns the raw representation of the id (e.g., as stored in TCUs)
    pub const fn raw(&self) -> u16 {
        self.id
    }
}

impl fmt::Display for TileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "C{}T{:02}", self.chip(), self.tile())
    }
}

cfg_if! {
    if #[cfg(target_vendor = "gem5")] {
        /// The total number of endpoints in each TCU
        pub const TOTAL_EPS: EpId = 192;
        /// The number of available endpoints in each TCU
        pub const AVAIL_EPS: EpId = TOTAL_EPS;
    }
    else {
        /// The total number of endpoints in each TCU
        pub const TOTAL_EPS: EpId = 128;
        /// The number of available endpoints in each TCU
        pub const AVAIL_EPS: EpId = TOTAL_EPS;
    }
}

pub const PMEM_PROT_EPS: usize = 4;

/// The send EP for kernel calls from TileMux
pub const KPEX_SEP: EpId = PMEM_PROT_EPS as EpId + 0;
/// The receive EP for kernel calls from TileMux
pub const KPEX_REP: EpId = PMEM_PROT_EPS as EpId + 1;
/// The receive EP for sidecalls from the kernel for TileMux
pub const TMSIDE_REP: EpId = PMEM_PROT_EPS as EpId + 2;
/// The reply EP for sidecalls from the kernel for TileMux
pub const TMSIDE_RPLEP: EpId = PMEM_PROT_EPS as EpId + 3;

/// The send EP offset for system calls
pub const SYSC_SEP_OFF: EpId = 0;
/// The receive EP offset for system calls
pub const SYSC_REP_OFF: EpId = 1;
/// The receive EP offset for upcalls from the kernel
pub const UPCALL_REP_OFF: EpId = 2;
/// The reply EP offset for upcalls from the kernel
pub const UPCALL_RPLEP_OFF: EpId = 3;
/// The default receive EP offset
pub const DEF_REP_OFF: EpId = 4;
/// The pager send EP offset
pub const PG_SEP_OFF: EpId = 5;
/// The pager receive EP offset
pub const PG_REP_OFF: EpId = 6;

/// The offset of the first user EP
pub const FIRST_USER_EP: EpId = PMEM_PROT_EPS as EpId + 4;
/// The number of standard EPs
pub const STD_EPS_COUNT: usize = 7;

/// An invalid endpoint ID
pub const INVALID_EP: EpId = 0xFFFF;
/// The reply EP for messages that want to disable replies
pub const NO_REPLIES: EpId = INVALID_EP;
/// Represents unlimited credits for send EPs
pub const UNLIM_CREDITS: u32 = 0x3F;

/// The base address of the TCU's MMIO area
pub const MMIO_ADDR: usize = 0xF000_0000;
/// The size of the TCU's MMIO area
pub const MMIO_SIZE: usize = cfg::PAGE_SIZE * 2;
/// The base address of the TCU's private MMIO area
pub const MMIO_PRIV_ADDR: usize = MMIO_ADDR + MMIO_SIZE;
/// The size of the TCU's private MMIO area (including config space on HW)
pub const MMIO_PRIV_SIZE: usize = cfg::PAGE_SIZE * 2;

/// The number of external registers
pub const EXT_REGS: usize = 2;
/// The number of unprivileged registers
pub const UNPRIV_REGS: usize = 5;
/// The number of registers per EP
pub const EP_REGS: usize = 3;
/// The number of PRINT registers
pub const PRINT_REGS: usize = 32;

int_enum! {
    /// The external registers
    pub struct ExtReg : Reg {
        /// Stores the privileged flag (for now)
        const FEATURES      = 0x0;
        /// For external commands
        const EXT_CMD       = 0x1;
    }
}

bitflags! {
    /// The status flag for the [`ExtReg::FEATURES`] register
    #[allow(dead_code)]
    pub struct FeatureFlags : Reg {
        /// Whether the tile is privileged
        const PRIV          = 1 << 0;
    }
}

int_enum! {
    /// The privileged registers
    #[allow(dead_code)]
    pub struct PrivReg : Reg {
        /// For core requests
        const CORE_REQ      = 0x0;
        /// For privileged commands
        const PRIV_CMD      = 0x1;
        /// The argument for privileged commands
        const PRIV_CMD_ARG  = 0x2;
        /// The current activity
        const CUR_ACT       = 0x3;
        /// Used to ack IRQ requests
        const CLEAR_IRQ     = 0x4;
    }
}

int_enum! {
    /// The unprivileged registers
    #[allow(dead_code)]
    pub struct UnprivReg : Reg {
        /// Starts commands and signals their completion
        const COMMAND       = 0x0;
        /// Specifies the data address and size
        const DATA          = 0x1;
        /// Specifies an additional argument
        const ARG1          = 0x2;
        /// The current time in nanoseconds
        const CUR_TIME      = 0x3;
        /// Prints a line into the gem5 log
        const PRINT         = 0x4;
    }
}

int_enum! {
    /// The config registers (hardware only)
    #[allow(dead_code)]
    pub struct ConfigReg : Reg {
        /// Enables/disables the instruction trace
        const INSTR_TRACE   = 0xD;
    }
}

int_enum! {
    /// The different endpoint types
    pub struct EpType : u64 {
        /// Invalid endpoint (unusable)
        const INVALID     = 0x0;
        /// Send endpoint
        const SEND        = 0x1;
        /// Receive endpoint
        const RECEIVE     = 0x2;
        /// Memory endpoint
        const MEMORY      = 0x3;
    }
}

int_enum! {
    /// The commands
    pub struct CmdOpCode : u64 {
        /// The idle command has no effect
        const IDLE          = 0x0;
        /// Sends a message
        const SEND          = 0x1;
        /// Replies to a message
        const REPLY         = 0x2;
        /// Reads from external memory
        const READ          = 0x3;
        /// Writes to external memory
        const WRITE         = 0x4;
        /// Fetches a message
        const FETCH_MSG     = 0x5;
        /// Acknowledges a message
        const ACK_MSG       = 0x6;
        /// Puts the CU to sleep
        const SLEEP         = 0x7;
    }
}

int_enum! {
    /// The privileged commands
    pub struct PrivCmdOpCode : Reg {
        /// The idle command has no effect
        const IDLE        = 0;
        /// Invalidate a single TLB entry
        const INV_PAGE    = 1;
        /// Invalidate all TLB entries
        const INV_TLB     = 2;
        /// Insert an entry into the TLB
        const INS_TLB     = 3;
        /// Changes the activity
        const XCHG_ACT    = 4;
        /// Sets the timer
        const SET_TIMER   = 5;
        /// Abort the current command
        const ABORT_CMD   = 6;
    }
}

int_enum! {
    /// The external commands
    pub struct ExtCmdOpCode : Reg {
        /// The idle command has no effect
        const IDLE        = 0;
        /// Invalidate and endpoint, if possible
        const INV_EP      = 1;
        /// Reset the CU
        const RESET       = 2;
    }
}

int_enum! {
    /// The TCU-internal IRQ ids to clear IRQs
    pub struct IRQ : Reg {
        /// The core request IRQ
        const CORE_REQ  = 0;
        /// The timer IRQ
        const TIMER     = 1;
    }
}

/// A foreign-msg core request, that is sent by the TCU if a message was received for another activity
#[derive(Debug)]
pub struct CoreForeignReq {
    pub act: u16,
    pub ep: EpId,
}

impl CoreForeignReq {
    /// Decodes the given value from `CORE_REQ` into a `CoreForeignReq`
    pub fn new(req: Reg) -> Self {
        Self {
            act: (req >> 48) as u16,
            ep: ((req >> 2) & 0xFFFF) as EpId,
        }
    }
}

/// The TCU header
#[repr(C, packed)]
#[derive(Copy, Clone, Default, Debug)]
pub struct Header {
    other: u32,
    sender_ep: u16,
    reply_ep: u16,
    reply_label: u32,
    label: u32,
}

impl Header {
    /// Returns the length of the message payload in bytes
    pub fn length(&self) -> usize {
        (self.other >> 19) as usize & ((1 << 13) - 1)
    }

    /// Returns the label that has been assigned to the sender of the message
    pub fn label(&self) -> u32 {
        self.label
    }
}

/// The TCU message consisting of the header and the payload
#[repr(C, align(8))]
#[derive(Debug)]
pub struct Message {
    pub header: Header,
    pub data: [u8],
}

impl Message {
    /// Returns the message data as a slice of u64's
    pub fn as_words(&self) -> &[u64] {
        // safety: we trust the TCU
        unsafe {
            #[allow(clippy::cast_ptr_alignment)]
            let ptr = self.data.as_ptr() as *const u64;
            slice::from_raw_parts(ptr, self.header.length() / 8)
        }
    }
}

/// The TCU interface
pub struct TCU {}

impl TCU {
    /// Sends the given message via given endpoint.
    ///
    /// The `reply_ep` specifies the endpoint the reply is sent to. The label of the reply will be
    /// `reply_lbl`.
    ///
    /// # Errors
    ///
    /// If the number of left credits is not sufficient, the function returns
    /// [`MissCredits`](Code::NoCredits).
    #[inline(always)]
    pub fn send(
        ep: EpId,
        msg: &mem::MsgBuf,
        reply_lbl: Label,
        reply_ep: EpId,
    ) -> Result<(), Error> {
        Self::send_aligned(ep, msg.bytes().as_ptr(), msg.size(), reply_lbl, reply_ep)
    }

    /// Sends the message `msg` of `len` bytes via given endpoint. The message address needs to be
    /// 16-byte aligned and `msg`..`msg` + `len` cannot contain a page boundary.
    ///
    /// The `reply_ep` specifies the endpoint the reply is sent to. The label of the reply will be
    /// `reply_lbl`.
    ///
    /// # Errors
    ///
    /// If the number of left credits is not sufficient, the function returns
    /// [`MissCredits`](Code::NoCredits).
    #[inline(always)]
    pub fn send_aligned(
        ep: EpId,
        msg: *const u8,
        len: usize,
        reply_lbl: Label,
        reply_ep: EpId,
    ) -> Result<(), Error> {
        let msg_addr = msg as usize;
        log!(
            TCU,
            "TCU::send(ep={}, msg={:#x}, size={:#x}, reply_lbl={:#x}, reply_ep={})",
            ep,
            msg_addr,
            len,
            reply_lbl,
            reply_ep
        );

        Self::write_unpriv_reg(UnprivReg::DATA, Self::build_data(msg_addr, len));
        if reply_lbl != 0 {
            Self::write_unpriv_reg(UnprivReg::ARG1, reply_lbl as Reg);
        }
        Self::perform_send_reply(
            msg_addr,
            Self::build_cmd(ep, CmdOpCode::SEND, reply_ep as Reg),
        )
    }

    /// Sends the given message as reply to `msg`.
    #[inline(always)]
    pub fn reply(ep: EpId, reply: &mem::MsgBuf, msg_off: usize) -> Result<(), Error> {
        Self::reply_aligned(ep, reply.bytes().as_ptr(), reply.size(), msg_off)
    }

    /// Sends the given message as reply to `msg`. The message address needs to be 16-byte aligned
    /// and `reply`..`reply` + `len` cannot contain a page boundary.
    #[inline(always)]
    pub fn reply_aligned(
        ep: EpId,
        reply: *const u8,
        len: usize,
        msg_off: usize,
    ) -> Result<(), Error> {
        let reply_addr = reply as usize;
        log!(
            TCU,
            "TCU::reply(ep={}, reply={:#x}, size={:#x}, msg_off={:#x})",
            ep,
            reply_addr,
            len,
            msg_off
        );

        Self::write_unpriv_reg(UnprivReg::DATA, Self::build_data(reply_addr, len));

        Self::perform_send_reply(
            reply_addr,
            Self::build_cmd(ep, CmdOpCode::REPLY, msg_off as Reg),
        )
    }

    #[inline(always)]
    fn perform_send_reply(msg_addr: usize, cmd: Reg) -> Result<(), Error> {
        loop {
            Self::write_unpriv_reg(UnprivReg::COMMAND, cmd);

            match Self::get_error() {
                Ok(_) => break Ok(()),
                Err(e) if e.code() == Code::TranslationFault => {
                    Self::handle_xlate_fault(msg_addr, Perm::R);
                    // retry the access
                    continue;
                },
                Err(e) => break Err(e),
            }
        }
    }

    /// Reads `size` bytes from offset `off` in the memory region denoted by the endpoint into `data`.
    #[inline(always)]
    pub fn read(ep: EpId, data: *mut u8, size: usize, off: goff) -> Result<(), Error> {
        log!(
            TCU,
            "TCU::read(ep={}, data={:#x}, size={:#x}, off={:#x})",
            ep,
            data as usize,
            size,
            off
        );

        let res = Self::perform_transfer(ep, data as usize, size, off, CmdOpCode::READ);
        // ensure that the CPU is not reading the read data before the TCU is finished
        // note that x86 needs SeqCst here, because the Acquire/Release fence is implemented empty
        atomic::fence(atomic::Ordering::SeqCst);
        res
    }

    /// Writes `size` bytes from `data` to offset `off` in the memory region denoted by the endpoint.
    #[inline(always)]
    pub fn write(ep: EpId, data: *const u8, size: usize, off: goff) -> Result<(), Error> {
        log!(
            TCU,
            "TCU::write(ep={}, data={:#x}, size={:#x}, off={:#x})",
            ep,
            data as usize,
            size,
            off
        );

        // ensure that the TCU is not reading the data before the CPU has written everything
        atomic::fence(atomic::Ordering::SeqCst);
        Self::perform_transfer(ep, data as usize, size, off, CmdOpCode::WRITE)
    }

    #[inline(always)]
    fn perform_transfer(
        ep: EpId,
        mut data: usize,
        mut size: usize,
        mut off: goff,
        cmd: CmdOpCode,
    ) -> Result<(), Error> {
        while size > 0 {
            let amount = cmp::min(size, cfg::PAGE_SIZE - (data & cfg::PAGE_MASK));

            Self::write_unpriv_reg(UnprivReg::DATA, Self::build_data(data, amount));
            Self::write_unpriv_reg(UnprivReg::ARG1, off as Reg);
            Self::write_unpriv_reg(UnprivReg::COMMAND, Self::build_cmd(ep, cmd, 0));

            if let Err(e) = Self::get_error() {
                if e.code() == Code::TranslationFault {
                    Self::handle_xlate_fault(
                        data,
                        if cmd == CmdOpCode::READ {
                            Perm::W
                        }
                        else {
                            Perm::R
                        },
                    );
                    // retry the access
                    continue;
                }
                else {
                    return Err(e);
                }
            }

            size -= amount;
            data += amount;
            off += amount as goff;
        }
        Ok(())
    }

    #[cold]
    fn handle_xlate_fault(addr: usize, perm: Perm) {
        // report translation fault to TileMux or whoever handles the call; ignore errors, we won't
        // get back here if TileMux cannot resolve the fault.
        arch::tmabi::call2(tmif::Operation::TRANSL_FAULT, addr, perm.bits() as usize).ok();
    }

    /// Tries to fetch a new message from the given endpoint.
    #[inline(always)]
    pub fn fetch_msg(ep: EpId) -> Option<usize> {
        Self::write_unpriv_reg(
            UnprivReg::COMMAND,
            Self::build_cmd(ep, CmdOpCode::FETCH_MSG, 0),
        );
        Self::get_error().ok()?;
        let msg = Self::read_unpriv_reg(UnprivReg::ARG1);
        if msg != !0 {
            Some(msg as usize)
        }
        else {
            None
        }
    }

    /// Assuming that `ep` is a receive EP, the function returns whether there are unread messages.
    #[inline(always)]
    pub fn has_msgs(ep: EpId) -> bool {
        let r2 = Self::read_ep_reg(ep, 2);
        (r2 >> 32) != 0
    }

    /// Returns true if the given endpoint is valid, i.e., a SEND, RECEIVE, or MEMORY endpoint
    #[inline(always)]
    pub fn is_valid(ep: EpId) -> bool {
        let r0 = Self::read_ep_reg(ep, 0);
        (r0 & 0x7) != EpType::INVALID.val
    }

    /// Returns the number of credits for the given endpoint
    pub fn credits(ep: EpId) -> Result<u32, Error> {
        let r0 = Self::read_ep_reg(ep, 0);
        if (r0 & 0x7) != EpType::SEND.val {
            return Err(Error::new(Code::NoSEP));
        }
        let cur = (r0 >> 19) & 0x3F;
        Ok(cur as u32)
    }

    /// Returns true if the given endpoint is a SEND EP and has missing credits
    pub fn has_missing_credits(ep: EpId) -> bool {
        let r0 = Self::read_ep_reg(ep, 0);
        if (r0 & 0x7) != EpType::SEND.val {
            return false;
        }
        let cur = (r0 >> 19) & 0x3F;
        let max = (r0 >> 25) & 0x3F;
        cur < max
    }

    /// Unpacks the given memory EP into the tile id, address, size, and permissions.
    ///
    /// Returns `Some((<tile>, <address>, <size>, <perm>))` if the given EP is a memory EP, or `None`
    /// otherwise.
    pub fn unpack_mem_ep(ep: EpId) -> Option<(TileId, u64, u64, Perm)> {
        let r0 = Self::read_ep_reg(ep, 0);
        let r1 = Self::read_ep_reg(ep, 1);
        let r2 = Self::read_ep_reg(ep, 2);
        Self::unpack_mem_regs(&[r0, r1, r2])
    }

    /// Unpacks the given memory EP registers into the tile id, address, size, and permissions.
    ///
    /// Returns `Some((<tile>, <address>, <size>, <perm>))` if the given registers represent a memory
    /// EP, or `None` otherwise.
    pub fn unpack_mem_regs(regs: &[Reg]) -> Option<(TileId, u64, u64, Perm)> {
        if (regs[0] & 0x7) != EpType::MEMORY.val {
            return None;
        }

        let tileid = Self::nocid_to_tileid(((regs[0] >> 23) & 0x3FFF) as u16);
        let perm = Perm::from_bits_truncate((regs[0] as u32 >> 19) & 0x3);
        Some((tileid, regs[1], regs[2], perm))
    }

    /// Marks the given message for receive endpoint `ep` as read
    #[inline(always)]
    pub fn ack_msg(ep: EpId, msg_off: usize) -> Result<(), Error> {
        // ensure that we are really done with the message before acking it
        atomic::fence(atomic::Ordering::SeqCst);
        Self::write_unpriv_reg(
            UnprivReg::COMMAND,
            Self::build_cmd(ep, CmdOpCode::ACK_MSG, msg_off as Reg),
        );
        Self::get_error()
    }

    /// Waits until the current command is completed and returns the error, if any occurred
    #[inline(always)]
    pub fn get_error() -> Result<(), Error> {
        loop {
            let cmd = Self::read_unpriv_reg(UnprivReg::COMMAND);
            if (cmd & 0xF) == CmdOpCode::IDLE.val {
                let err = (cmd >> 20) & 0x1F;
                return Result::from(Code::from(err as u32));
            }
        }
    }

    /// Returns the time in nanoseconds since boot
    #[inline(always)]
    pub(crate) fn nanotime() -> u64 {
        Self::read_unpriv_reg(UnprivReg::CUR_TIME)
    }

    /// Puts the CU to sleep until the CU is woken up (e.g., by a message reception).
    #[inline(always)]
    pub fn sleep() -> Result<(), Error> {
        Self::wait_for_msg(INVALID_EP, None)
    }

    /// Puts the CU to sleep until a message arrives at receive EP `ep`.
    #[inline(always)]
    pub fn wait_for_msg(ep: EpId, timeout: Option<u64>) -> Result<(), Error> {
        if timeout.is_some() {
            return Err(Error::new(Code::NotSup));
        }

        Self::write_unpriv_reg(
            UnprivReg::COMMAND,
            Self::build_cmd(0, CmdOpCode::SLEEP, ep as u64),
        );
        Self::get_error()
    }

    /// Drops all messages in the receive buffer of given receive EP that have the given label.
    pub fn drop_msgs_with(buf_addr: usize, ep: EpId, label: Label) {
        // we assume that the one that used the label can no longer send messages. thus, if there
        // are no messages yet, we are done.
        let unread = Self::read_ep_reg(ep, 2) >> 32;
        if unread == 0 {
            return;
        }

        let r0 = Self::read_ep_reg(ep, 0);
        let buf_size = 1 << ((r0 >> 35) & 0x3F);
        let msg_size = (r0 >> 41) & 0x3F;
        for i in 0..buf_size {
            if (unread & (1 << i)) != 0 {
                let msg = Self::offset_to_msg(buf_addr, i << msg_size);
                if msg.header.label == label {
                    Self::ack_msg(ep, i << msg_size).ok();
                }
            }
        }
    }

    /// Prints the given message into the gem5 log
    pub fn print(s: &[u8]) -> usize {
        let regs = EXT_REGS + UNPRIV_REGS + EP_REGS * TOTAL_EPS as usize;
        let mut buffer = MMIO_ADDR + regs * 8;

        let s = &s[0..cmp::min(s.len(), PRINT_REGS * mem::size_of::<Reg>() - 1)];

        // copy string into aligned buffer (just to be sure)
        let mut words = [0u64; 32];
        unsafe {
            words
                .as_mut_ptr()
                .cast::<u8>()
                .copy_from(s.as_ptr(), s.len())
        };

        let num = math::round_up(s.len(), 8) / 8;
        for c in words.iter().take(num) {
            // safety: we know that the address is within the MMIO region of the TCU
            unsafe { arch::cpu::write8b(buffer, *c) };
            buffer += 8;
        }

        Self::write_unpriv_reg(UnprivReg::PRINT, s.len() as u64);
        // wait until the print was carried out
        while Self::read_unpriv_reg(UnprivReg::PRINT) != 0 {}
        s.len()
    }

    /// Writes the code-coverage results in `data` to "$M3_OUT/coverage-<tile>-<act>.profraw".
    pub fn write_coverage(data: &[u8], act: u64) {
        Self::write_unpriv_reg(
            UnprivReg::PRINT,
            act << 56 | (data.as_ptr() as u64) << 24 | data.len() as u64,
        );
        // wait until the coverage was written
        while Self::read_unpriv_reg(UnprivReg::PRINT) != 0 {}
    }

    /// Translates the offset `off` to the message address, using `base` as the base address of the
    /// message's receive buffer
    pub fn offset_to_msg(base: usize, off: usize) -> &'static Message {
        // safety: the cast is okay because we trust the TCU
        unsafe {
            let head = (base + off) as *const Header;
            let slice = [base + off, (*head).length()];
            intrinsics::transmute(slice)
        }
    }

    /// Translates the message address `msg` to the offset within its receive buffer, using `base`
    /// as the base address of the receive buffer
    pub fn msg_to_offset(base: usize, msg: &Message) -> usize {
        let addr = msg as *const _ as *const u8 as usize;
        addr - base
    }

    /// Returns the injected IRQ (assuming that a IRQ has been injected and was not cleared yet)
    pub fn get_irq() -> IRQ {
        IRQ::from(Self::read_priv_reg(PrivReg::CLEAR_IRQ))
    }

    /// Clears the given IRQ to notify the TCU that the IRQ has been accepted
    pub fn clear_irq(irq: IRQ) {
        Self::write_priv_reg(PrivReg::CLEAR_IRQ, irq.val);
    }

    /// Returns the current core request
    pub fn get_core_req() -> Option<CoreForeignReq> {
        let req = Self::read_priv_reg(PrivReg::CORE_REQ);
        match req & 0x3 {
            0x2 => Some(CoreForeignReq::new(req)),
            _ => None,
        }
    }

    /// Provides the TCU with the response to a foreign-msg core request
    pub fn set_foreign_resp() {
        Self::write_priv_reg(PrivReg::CORE_REQ, 0x1)
    }

    /// Returns the current activity with its id and message count
    pub fn get_cur_activity() -> Reg {
        Self::read_priv_reg(PrivReg::CUR_ACT)
    }

    /// Aborts the current command or activity, specified in `req`, and returns the command register to
    /// use for a retry later.
    pub fn abort_cmd() -> Result<Reg, Error> {
        // save the old value before aborting
        let cmd_reg = Self::read_unpriv_reg(UnprivReg::COMMAND);
        // ensure that we read the command register before the abort has been executed
        atomic::fence(atomic::Ordering::SeqCst);
        Self::write_priv_reg(PrivReg::PRIV_CMD, PrivCmdOpCode::ABORT_CMD.val);

        loop {
            let cmd = Self::read_priv_reg(PrivReg::PRIV_CMD);
            if (cmd & 0xF) == PrivCmdOpCode::IDLE.val {
                let err = (cmd >> 4) & 0x1F;
                if err != 0 {
                    break Err(Error::new(Code::from(err as u32)));
                }
                else if (cmd >> 9) == 0 {
                    // if the command was finished successfully, use the current command register
                    // to ensure that we don't forget the error code
                    break Ok(Self::read_unpriv_reg(UnprivReg::COMMAND));
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
        Self::write_priv_reg(PrivReg::PRIV_CMD, PrivCmdOpCode::XCHG_ACT.val | (nact << 9));
        Self::get_priv_error()?;
        Ok(Self::read_priv_reg(PrivReg::PRIV_CMD_ARG))
    }

    /// Invalidates the TCU's TLB
    pub fn invalidate_tlb() {
        Self::write_priv_reg(PrivReg::PRIV_CMD, PrivCmdOpCode::INV_TLB.val);
        Self::wait_priv_cmd();
    }

    /// Invalidates the entry with given address space id and virtual address in the TCU's TLB
    pub fn invalidate_page(asid: u16, virt: usize) {
        let val = ((asid as Reg) << 41) | ((virt as Reg) << 9) | PrivCmdOpCode::INV_PAGE.val;
        Self::write_priv_reg(PrivReg::PRIV_CMD, val);
        Self::wait_priv_cmd();
    }

    /// Inserts the given entry into the TCU's TLB
    pub fn insert_tlb(asid: u16, virt: usize, phys: u64, flags: PageFlags) -> Result<(), Error> {
        Self::write_priv_reg(PrivReg::PRIV_CMD_ARG, phys);
        atomic::fence(atomic::Ordering::SeqCst);
        let cmd = ((asid as Reg) << 41)
            | (((virt & !cfg::PAGE_MASK) as Reg) << 9)
            | ((flags.bits() as Reg) << 9)
            | PrivCmdOpCode::INS_TLB.val;
        Self::write_priv_reg(PrivReg::PRIV_CMD, cmd);
        Self::get_priv_error()
    }

    /// Sets the timer to fire in `delay_ns` nanoseconds if `delay_ns` is nonzero. Otherwise, unsets
    /// the timer.
    pub fn set_timer(delay_ns: u64) -> Result<(), Error> {
        Self::write_priv_reg(
            PrivReg::PRIV_CMD,
            PrivCmdOpCode::SET_TIMER.val | (delay_ns << 9),
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
            let cmd = Self::read_priv_reg(PrivReg::PRIV_CMD);
            if (cmd & 0xF) == PrivCmdOpCode::IDLE.val {
                return Code::from(((cmd >> 4) & 0x1F) as u32);
            }
        }
    }

    /// Enables or disables instruction tracing
    pub fn set_trace_instrs(enable: bool) {
        Self::write_cfg_reg(ConfigReg::INSTR_TRACE, enable as Reg);
    }

    /// Returns the value of the given unprivileged register
    pub fn read_unpriv_reg(reg: UnprivReg) -> Reg {
        Self::read_reg(EXT_REGS + reg.val as usize)
    }

    /// Sets the value of the given unprivileged register to `val`
    pub fn write_unpriv_reg(reg: UnprivReg, val: Reg) {
        Self::write_reg(EXT_REGS + reg.val as usize, val)
    }

    fn write_cfg_reg(reg: ConfigReg, val: Reg) {
        Self::write_reg(
            ((cfg::PAGE_SIZE * 3) / mem::size_of::<Reg>()) + reg.val as usize,
            val,
        )
    }

    fn read_ep_reg(ep: EpId, reg: usize) -> Reg {
        Self::read_reg(EXT_REGS + UNPRIV_REGS + EP_REGS * ep as usize + reg)
    }

    fn read_priv_reg(reg: PrivReg) -> Reg {
        Self::read_reg(((cfg::PAGE_SIZE * 2) / mem::size_of::<Reg>()) + reg.val as usize)
    }

    fn write_priv_reg(reg: PrivReg, val: Reg) {
        Self::write_reg(
            ((cfg::PAGE_SIZE * 2) / mem::size_of::<Reg>()) + reg.val as usize,
            val,
        )
    }

    fn read_reg(idx: usize) -> Reg {
        // safety: we know that the address is within the MMIO region of the TCU
        unsafe { arch::cpu::read8b(MMIO_ADDR + idx * 8) }
    }

    fn write_reg(idx: usize, val: Reg) {
        // safety: as above
        unsafe { arch::cpu::write8b(MMIO_ADDR + idx * 8, val) };
    }

    fn build_data(addr: usize, size: usize) -> Reg {
        addr as Reg | (size as Reg) << 32
    }

    fn build_cmd(ep: EpId, cmd: CmdOpCode, arg: Reg) -> Reg {
        cmd.val as Reg | ((ep as Reg) << 4) | (arg << 25)
    }
}

static TILE_IDS: LazyReadOnlyCell<[u16; cfg::MAX_TILES * cfg::MAX_CHIPS]> =
    LazyReadOnlyCell::default();

impl TCU {
    pub fn init_tileid_translation(tile_ids: &[u64], collect: bool) -> Vec<TileId> {
        let mut ids = [0u16; cfg::MAX_TILES * cfg::MAX_CHIPS];

        let mut log_ids = Vec::new();
        let mut log_chip = 0;
        let mut log_tile = 0;
        let mut phys_chip = None;
        for id in tile_ids {
            let tid = TileId::new_from_raw(*id as u16);

            if phys_chip.is_some() {
                if phys_chip.unwrap() != tid.chip() {
                    phys_chip = Some(tid.chip());
                    log_chip += 1;
                    log_tile = 0;
                }
                else {
                    log_tile += 1;
                }
            }
            else {
                phys_chip = Some(tid.chip());
            }

            ids[log_chip * cfg::MAX_TILES + log_tile] = tid.raw();
            if collect {
                log_ids.push(TileId::new(log_chip as u8, log_tile as u8));
            }
        }

        TILE_IDS.set(ids);
        log_ids
    }

    pub fn tileid_to_nocid(tile: TileId) -> u16 {
        TILE_IDS.get()[tile.chip() as usize * cfg::MAX_TILES + tile.tile() as usize]
    }

    pub fn nocid_to_tileid(tile: u16) -> TileId {
        for (i, id) in TILE_IDS.get().iter().enumerate() {
            if *id == tile {
                let chip = i / cfg::MAX_TILES;
                let tile = i % cfg::MAX_TILES;
                return TileId::new(chip as u8, tile as u8);
            }
        }
        unreachable!();
    }

    pub fn config_recv(
        regs: &mut [Reg],
        act: ActId,
        buf: goff,
        buf_ord: u32,
        msg_ord: u32,
        reply_eps: Option<EpId>,
    ) {
        regs[0] = EpType::RECEIVE.val
            | ((act as Reg) << 3)
            | ((reply_eps.unwrap_or(NO_REPLIES) as Reg) << 19)
            | (((buf_ord - msg_ord) as Reg) << 35)
            | ((msg_ord as Reg) << 41);
        regs[1] = buf as Reg;
        regs[2] = 0;
    }

    pub fn config_send(
        regs: &mut [Reg],
        act: ActId,
        lbl: Label,
        tile: TileId,
        dst_ep: EpId,
        msg_order: u32,
        credits: u32,
    ) {
        regs[0] = EpType::SEND.val
            | ((act as Reg) << 3)
            | ((credits as Reg) << 19)
            | ((credits as Reg) << 25)
            | ((msg_order as Reg) << 31);
        regs[1] = (dst_ep as Reg) | ((Self::tileid_to_nocid(tile) as Reg) << 16);
        regs[2] = lbl as Reg;
    }

    pub fn config_mem(
        regs: &mut [Reg],
        act: ActId,
        tile: TileId,
        addr: goff,
        size: usize,
        perm: Perm,
    ) {
        regs[0] = EpType::MEMORY.val
            | ((act as Reg) << 3)
            | ((perm.bits() as Reg) << 19)
            | ((Self::tileid_to_nocid(tile) as Reg) << 23);
        regs[1] = addr as Reg;
        regs[2] = size as Reg;
    }

    /// Configures the given endpoint
    pub fn set_ep_regs(ep: EpId, regs: &[Reg]) {
        let off = EXT_REGS + UNPRIV_REGS + EP_REGS * ep as usize;
        let addr = MMIO_ADDR + off * 8;
        for (i, r) in regs.iter().enumerate() {
            unsafe {
                arch::cpu::write8b(addr + i * mem::size_of::<Reg>(), *r);
            }
        }
    }

    /// Returns the MMIO address for the given external register
    pub fn ext_reg_addr(reg: ExtReg) -> usize {
        MMIO_ADDR + reg.val as usize * 8
    }

    /// Returns the MMIO address of the given endpoint registers
    pub fn ep_regs_addr(ep: EpId) -> usize {
        MMIO_ADDR + (EXT_REGS + UNPRIV_REGS + EP_REGS * ep as usize) * 8
    }
}
