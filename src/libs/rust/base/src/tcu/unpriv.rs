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

//! The TCU's unprivileged interface

use core::cmp;
use core::intrinsics;

use num_enum::IntoPrimitive;

use crate::arch::{CPUOps, CPU};
use crate::cell::StaticCell;
use crate::cfg;
use crate::env;
use crate::errors::{Code, Error};
use crate::kif::Perm;
use crate::mem::PhysAddr;
use crate::mem::{self, GlobOff, MaybeUninit, PhysAddrRaw, VirtAddr};
use crate::tmif;
use crate::util::math;

use crate::tcu::{
    EpId, EpType, Header, Label, Message, Reg, TileId, EXT_REGS, INVALID_EP, MMIO_ADDR, PRINT_REGS,
    TCU, UNPRIV_REGS,
};

/// The commands
#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive)]
#[repr(u64)]
pub enum CmdOpCode {
    /// The idle command has no effect
    Idle,
    /// Sends a message
    Send,
    /// Replies to a message
    Reply,
    /// Reads from external memory
    Read,
    /// Writes to external memory
    Write,
    /// Fetches a message
    FetchMsg,
    /// Acknowledges a message
    AckMsg,
    /// Unfreezes an endpoint
    Unfreeze,
    /// Makes an endpoint dynamic
    Mkdyn,
    /// Puts the CU to sleep
    Sleep,
}

/// The unprivileged registers
#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive)]
#[repr(u64)]
pub enum UnprivReg {
    /// Starts commands and signals their completion
    Command,
    /// Specifies the data address
    DataAddr,
    /// Specifies the data size
    DataSize,
    /// Specifies an additional argument
    Arg1,
    /// The current time in nanoseconds
    CurTime,
    /// Prints a line into the gem5 log
    Print,
}

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
        let msg_addr = VirtAddr::from(msg);
        Self::write_data(msg_addr, len);
        if reply_lbl != 0 {
            Self::write_unpriv_reg(UnprivReg::Arg1, reply_lbl as Reg);
        }
        Self::perform_send_reply(
            msg_addr,
            Self::build_cmd(ep, CmdOpCode::Send, reply_ep as Reg),
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
        let reply_addr = VirtAddr::from(reply);
        Self::write_data(reply_addr, len);

        Self::perform_send_reply(
            reply_addr,
            Self::build_cmd(ep, CmdOpCode::Reply, msg_off as Reg),
        )
    }

    #[inline(always)]
    fn perform_send_reply(msg_addr: VirtAddr, cmd: Reg) -> Result<(), Error> {
        loop {
            Self::write_unpriv_reg(UnprivReg::Command, cmd);

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
    pub fn read(ep: EpId, data: *mut u8, size: usize, off: GlobOff) -> Result<(), Error> {
        let res = Self::perform_transfer(ep, VirtAddr::from(data), size, off, CmdOpCode::Read);
        // ensure that the CPU is not reading the read data before the TCU is finished
        // note that x86 needs SeqCst here, because the Acquire/Release fence is implemented empty
        CPU::memory_barrier();
        res
    }

    /// Uses the TCU read command to read from the memory region denoted by the endpoint at offset
    /// `off` and stores the read data into the slice `data`. The number of bytes to read is defined
    /// by `data`.
    pub fn read_slice<T>(ep: EpId, data: &mut [T], off: GlobOff) -> Result<(), Error> {
        Self::read(
            ep,
            data.as_mut_ptr() as *mut u8,
            mem::size_of_val(data),
            off,
        )
    }

    /// Reads `mem::size_of::<T>()` bytes via the TCU read command from the memory region
    /// denoted by the endpoint at offset `off` and returns the data as an object of `T`.
    pub fn read_obj<T>(ep: EpId, off: GlobOff) -> Result<T, Error> {
        #[allow(clippy::uninit_assumed_init)]
        // safety: will be initialized in read_bytes
        let mut obj: T = unsafe { MaybeUninit::uninit().assume_init() };
        Self::read(ep, &mut obj as *mut T as *mut u8, mem::size_of::<T>(), off)?;
        Ok(obj)
    }

    /// Writes `size` bytes from `data` to offset `off` in the memory region denoted by the endpoint.
    #[inline(always)]
    pub fn write(ep: EpId, data: *const u8, size: usize, off: GlobOff) -> Result<(), Error> {
        // ensure that the TCU is not reading the data before the CPU has written everything
        CPU::memory_barrier();
        Self::perform_transfer(ep, VirtAddr::from(data), size, off, CmdOpCode::Write)
    }

    /// Writes `data` to offset `off` in the memory region denoted by the endpoint.
    pub fn write_slice<T>(ep: EpId, data: &[T], off: GlobOff) -> Result<(), Error> {
        Self::write(ep, data.as_ptr() as *const u8, mem::size_of_val(data), off)
    }

    /// Writes `obj` to offset `off` in the memory region denoted by the endpoint.
    pub fn write_obj<T>(ep: EpId, obj: &T, off: GlobOff) -> Result<(), Error> {
        Self::write(ep, obj as *const T as *const u8, mem::size_of::<T>(), off)
    }

    #[inline(always)]
    fn perform_transfer(
        ep: EpId,
        mut data: VirtAddr,
        mut size: usize,
        mut off: GlobOff,
        cmd: CmdOpCode,
    ) -> Result<(), Error> {
        while size > 0 {
            let amount = cmp::min(size, cfg::PAGE_SIZE - (data.as_local() & cfg::PAGE_MASK));

            Self::write_data(data, amount);
            Self::write_unpriv_reg(UnprivReg::Arg1, off as Reg);
            Self::write_unpriv_reg(UnprivReg::Command, Self::build_cmd(ep, cmd, 0));

            if let Err(e) = Self::get_error() {
                if e.code() == Code::TranslationFault {
                    Self::handle_xlate_fault(
                        data,
                        if cmd == CmdOpCode::Read {
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
            off += amount as GlobOff;
        }
        Ok(())
    }

    #[cold]
    pub fn handle_xlate_fault(addr: VirtAddr, perm: Perm) {
        // report translation fault to TileMux or whoever handles the call; ignore errors, we won't
        // get back here if TileMux cannot resolve the fault.
        tmif::xlate_fault(addr, perm).ok();
    }

    /// Tries to fetch a new message from the given endpoint.
    #[inline(always)]
    pub fn fetch_msg(ep: EpId) -> Option<usize> {
        Self::write_unpriv_reg(
            UnprivReg::Command,
            Self::build_cmd(ep, CmdOpCode::FetchMsg, 0),
        );
        Self::get_error().ok()?;
        let msg = Self::read_unpriv_reg(UnprivReg::Arg1);
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
        let unread = match env!("M3_TARGET") {
            "hw23" => Self::read_ep_reg(ep, 2) >> 32,
            _ => Self::read_ep_reg(ep, 3),
        };
        unread != 0
    }

    /// Returns true if the given endpoint is valid, i.e., a SEND, RECEIVE, or MEMORY endpoint
    #[inline(always)]
    pub fn is_valid(ep: EpId) -> bool {
        let r0 = Self::read_ep_reg(ep, 0);
        (r0 & 0x7) != EpType::Invalid.into()
    }

    /// Returns the number of credits for the given endpoint
    pub fn credits(ep: EpId) -> Result<u32, Error> {
        if let Some((cur, _max)) = Self::unpack_credits(ep) {
            Ok(cur as u32)
        }
        else {
            Err(Error::new(Code::NoSEP))
        }
    }

    /// Returns true if the given endpoint is a SEND EP and has missing credits
    pub fn has_missing_credits(ep: EpId) -> bool {
        if let Some((cur, max)) = Self::unpack_credits(ep) {
            cur < max
        }
        else {
            false
        }
    }

    fn unpack_credits(ep: EpId) -> Option<(u64, u64)> {
        let r0 = Self::read_ep_reg(ep, 0);
        if (r0 & 0x7) != EpType::Send.into() {
            return None;
        }
        let (cur, max) = match env!("M3_TARGET") {
            "hw23" => ((r0 >> 19) & 0x3F, (r0 >> 25) & 0x3F),
            _ => ((r0 >> 19) & 0x7F, (r0 >> 26) & 0x7F),
        };
        Some((cur, max))
    }

    /// Unpacks the given memory EP into the tile id, address, size, and permissions.
    ///
    /// Returns `Some((<tile>, <address>, <size>, <perm>))` if the given EP is a memory EP, or `None`
    /// otherwise.
    pub fn unpack_mem_ep(ep: EpId) -> Option<(TileId, GlobOff, GlobOff, Perm)> {
        let r0 = Self::read_ep_reg(ep, 0);
        let r1 = Self::read_ep_reg(ep, 1);
        let r2 = Self::read_ep_reg(ep, 2);
        Self::unpack_mem_regs(&[r0, r1, r2])
    }

    /// Unpacks the given memory EP registers into the tile id, address, size, and permissions.
    ///
    /// Returns `Some((<tile>, <address>, <size>, <perm>))` if the given registers represent a memory
    /// EP, or `None` otherwise.
    pub fn unpack_mem_regs(regs: &[Reg]) -> Option<(TileId, GlobOff, GlobOff, Perm)> {
        if (regs[0] & 0x7) != EpType::Memory.into() {
            return None;
        }

        let tileid = Self::nocid_to_tileid(((regs[0] >> 23) & 0x3FFF) as u16);
        let perm = Perm::from_bits_truncate((regs[0] as u32 >> 19) & 0x3);
        Some((tileid, regs[1], regs[2], perm))
    }

    /// Retrieves information on the given receive endpoint
    ///
    /// Returns `Some((<address>, <slot-size>, <slots>, <reply-EPs>))` if the EP is a receive EP or
    /// `None` otherwise.
    pub fn unpack_recv_ep(ep: EpId) -> Option<(PhysAddrRaw, u32, u32, EpId)> {
        let r0 = Self::read_ep_reg(ep, 0);
        let r1 = Self::read_ep_reg(ep, 1);

        if (r0 & 0x7) != EpType::Receive.into() {
            return None;
        }

        let (msg_order, slots) = match env!("M3_TARGET") {
            "hw23" => ((r0 >> 41) & 0x3F, (r0 >> 35) & 0x3F),
            _ => ((r0 >> 42) & 0x3F, (r0 >> 35) & 0x7F),
        };
        Some((
            r1 as PhysAddrRaw,
            msg_order as u32,
            slots as u32,
            ((r0 >> 19) & 0xFFFF) as EpId,
        ))
    }

    /// Checks whether the given receive EP is sane.
    ///
    /// The function ensures that it's actually a receive EP, that the buffer is as expected, and
    /// the reply EPs start after the given EP id.
    pub fn check_recv_ep(
        ep: EpId,
        buf_addr: PhysAddr,
        buf_size: usize,
        replies: bool,
    ) -> Result<(), Error> {
        let rinfo = TCU::unpack_recv_ep(ep).ok_or_else(|| Error::new(Code::KernelBroken))?;
        // check if the physical address and the buffer size is as expected (otherwise the
        // kernel could send us messages to overwrite specific areas of memory).
        if PhysAddr::new_raw(env::boot().tile_desc(), rinfo.0) != buf_addr {
            return Err(Error::new(Code::KernelBroken));
        }
        if (1 << (rinfo.1 + rinfo.2)) as usize != buf_size {
            return Err(Error::new(Code::KernelBroken));
        }
        // check that the reply EPs are at the expected position (otherwise the kernel could
        // let the TCU overwrite other send EPs and thereby trick us to send to unexpected
        // receivers).
        if (replies && rinfo.3 != ep + 1) || (!replies && rinfo.3 != INVALID_EP) {
            return Err(Error::new(Code::KernelBroken));
        }
        Ok(())
    }

    /// Returns true if the given EP is dynamic
    #[inline(always)]
    pub fn is_dynamic(ep: EpId) -> bool {
        let r0 = Self::read_ep_reg(ep, 0);
        ((r0 >> 62) & 0x1) != 0
    }

    /// Returns true if the given EP is frozen
    #[inline(always)]
    pub fn is_frozen(ep: EpId) -> bool {
        let r0 = Self::read_ep_reg(ep, 0);
        (r0 >> 63) != 0
    }

    /// Unfreezes an endpoint that has been changed by the kernel and was therefore frozen.
    #[inline(always)]
    pub fn unfreeze(ep: EpId) -> Result<(), Error> {
        Self::write_unpriv_reg(
            UnprivReg::Command,
            Self::build_cmd(ep, CmdOpCode::Unfreeze, 0),
        );
        Self::get_error()
    }

    /// Marks the given message for receive endpoint `ep` as read
    #[inline(always)]
    pub fn ack_msg(ep: EpId, msg_off: usize) -> Result<(), Error> {
        // ensure that we are really done with the message before acking it
        CPU::memory_barrier();
        Self::write_unpriv_reg(
            UnprivReg::Command,
            Self::build_cmd(ep, CmdOpCode::AckMsg, msg_off as Reg),
        );
        Self::get_error()
    }

    /// Makes an endpoint dynamic.
    ///
    /// Dynamic EPs are not frozen if the TCU is locked and can therefore be freely changed by the
    /// kernel.
    #[inline(always)]
    pub fn mkdyn(ep: EpId) -> Result<(), Error> {
        Self::write_unpriv_reg(UnprivReg::Command, Self::build_cmd(ep, CmdOpCode::Mkdyn, 0));
        Self::get_error()
    }

    /// Waits until the current command is completed and returns the error, if any occurred
    #[inline(always)]
    pub fn get_error() -> Result<(), Error> {
        loop {
            let cmd = Self::read_unpriv_reg(UnprivReg::Command);
            if (cmd & 0xF) == CmdOpCode::Idle.into() {
                let err = match env!("M3_TARGET") {
                    "hw23" => (cmd >> 20) & 0x1F,
                    _ => (cmd >> 20) & 0x3F,
                };
                return Result::from(Code::try_from(err as u32).unwrap());
            }
        }
    }

    /// Returns the time in nanoseconds since boot
    #[inline(always)]
    pub(crate) fn nanotime() -> u64 {
        let time = Self::read_unpriv_reg(UnprivReg::CurTime);
        match env!("M3_TARGET") {
            "hw" => time * 10,
            _ => time,
        }
    }

    /// Puts the CU to sleep until the CU is woken up (e.g., by a message reception).
    #[inline(always)]
    pub fn sleep() -> Result<(), Error> {
        Self::wait_for_msg(INVALID_EP, INVALID_EP, None)
    }

    /// Puts the CU to sleep until a message arrives at receive EP `rep` or `iep` is invalidated.
    #[inline(always)]
    pub fn wait_for_msg(rep: EpId, iep: EpId, timeout: Option<u64>) -> Result<(), Error> {
        if timeout.is_some() {
            return Err(Error::new(Code::NotSup));
        }

        Self::write_unpriv_reg(
            UnprivReg::Command,
            Self::build_cmd(0, CmdOpCode::Sleep, (iep as u64) << 16 | (rep as u64)),
        );
        Self::get_error()
    }

    /// Drops all messages in the receive buffer of given receive EP that have the given label.
    pub fn drop_msgs_with(buf_addr: VirtAddr, ep: EpId, label: Label) {
        // we assume that the one that used the label can no longer send messages. thus, if there
        // are no messages yet, we are done.
        let unread = match env!("M3_TARGET") {
            "hw23" => Self::read_ep_reg(ep, 3) >> 32,
            _ => Self::read_ep_reg(ep, 3),
        };
        if unread == 0 {
            return;
        }

        let r0 = Self::read_ep_reg(ep, 0);
        let (buf_size, msg_size) = match env!("M3_TARGET") {
            "hw23" => (1 << ((r0 >> 35) & 0x3F), (r0 >> 41) & 0x3F),
            _ => (1 << ((r0 >> 35) & 0x7F), (r0 >> 42) & 0x3F),
        };

        for i in 0..buf_size {
            if (unread & (1 << i)) != 0 {
                let msg = Self::offset_to_msg(buf_addr, i << msg_size);
                if msg.header.label() == label {
                    Self::ack_msg(ep, i << msg_size).ok();
                }
            }
        }
    }

    /// Prints the given message into the gem5 log
    pub fn print(s: &[u8]) -> usize {
        let regs = match env!("M3_TARGET") {
            "hw23" => EXT_REGS + UNPRIV_REGS + (128 * super::EP_REGS),
            _ => EXT_REGS + UNPRIV_REGS,
        };

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
        // safety: we know that the address is within the MMIO region of the TCU
        unsafe {
            let mut buffer = (MMIO_ADDR.as_mut_ptr::<Reg>()).add(regs);
            for c in words.iter().take(num) {
                CPU::write8b(buffer, *c);
                buffer = buffer.add(1);
            }
        }

        // limit the UDP packet rate a bit to avoid packet drops
        if env::boot().platform == env::Platform::Hw {
            static LAST_PRINT: StaticCell<u64> = StaticCell::new(0);
            loop {
                if (Self::read_unpriv_reg(UnprivReg::CurTime) - LAST_PRINT.get()) >= 100000 {
                    break;
                }
            }
            LAST_PRINT.set(Self::read_unpriv_reg(UnprivReg::CurTime));
        }

        Self::write_unpriv_reg(UnprivReg::Print, s.len() as u64);
        // wait until the print was carried out
        while Self::read_unpriv_reg(UnprivReg::Print) != 0 {}
        s.len()
    }

    /// Writes the code-coverage results in `data` to "$M3_OUT/coverage-`tile`-`act`.profraw".
    pub fn write_coverage(data: &[u8], act: u64) {
        Self::write_unpriv_reg(
            UnprivReg::Print,
            act << 56 | (data.as_ptr() as u64) << 24 | data.len() as u64,
        );
        // wait until the coverage was written
        while Self::read_unpriv_reg(UnprivReg::Print) != 0 {}
    }

    /// Translates the offset `off` to the message address, using `base` as the base address of the
    /// message's receive buffer
    pub fn offset_to_msg(base: VirtAddr, off: usize) -> &'static Message {
        // safety: the cast is okay because we trust the TCU
        unsafe {
            let head = (base.as_local() + off) as *const Header;
            let slice = [base.as_local() + off, (*head).length()];
            intrinsics::transmute(slice)
        }
    }

    /// Translates the message address `msg` to the offset within its receive buffer, using `base`
    /// as the base address of the receive buffer
    pub fn msg_to_offset(base: VirtAddr, msg: &Message) -> usize {
        let addr = msg as *const _ as *const u8 as usize;
        addr - base.as_local()
    }

    fn build_cmd(ep: EpId, cmd: CmdOpCode, arg: Reg) -> Reg {
        match env!("M3_TARGET") {
            "hw23" => cmd as Reg | ((ep as Reg) << 4) | (arg << 25),
            _ => cmd as Reg | ((ep as Reg) << 4) | (arg << 26),
        }
    }
}
