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

use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::arch::{CPUOps, CPU};
use crate::cell::LazyReadOnlyCell;
use crate::cell::StaticCell;
use crate::cfg;
use crate::env;
use crate::errors::{Code, Error};
use crate::kif::{PageFlags, Perm};
use crate::mem::{self, GlobOff, MaybeUninit, PhysAddr, PhysAddrRaw, VirtAddr, VirtAddrRaw};
use crate::serialize::{Deserialize, Serialize};
use crate::tmif;
use crate::util::math;

/// A TCU register
pub type Reg = u64;
/// An endpoint id
pub type EpId = u16;
/// A TCU label used in send EPs
#[cfg(feature = "hw22")]
pub type Label = u32;
#[cfg(not(feature = "hw22"))]
pub type Label = u64;
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

pub const PMEM_PROT_EPS: usize = 4;
pub const TILEMUX_EPS: usize = 4;

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
pub const FIRST_USER_EP: EpId = PMEM_PROT_EPS as EpId + TILEMUX_EPS as EpId;
/// The number of standard EPs
pub const STD_EPS_COUNT: usize = 7;

/// An invalid endpoint ID
pub const INVALID_EP: EpId = 0xFFFF;
/// The reply EP for messages that want to disable replies
pub const NO_REPLIES: EpId = INVALID_EP;

/// The base address of the TCU's MMIO area
pub const MMIO_ADDR: VirtAddr = VirtAddr::new(0xF000_0000);
/// The size of the TCU's privileged MMIO area
pub const MMIO_PRIV_SIZE: usize = cfg::PAGE_SIZE;

/// The number of PRINT registers
pub const PRINT_REGS: usize = 32;
cfg_if! {
    if #[cfg(feature = "hw22")] {
        /// The number of external registers
        pub const EXT_REGS: usize = 2;
        /// The number of unprivileged registers
        pub const UNPRIV_REGS: usize = 5;
    }
    else if #[cfg(feature = "hw23")] {
        /// The number of external registers
        pub const EXT_REGS: usize = 3;
        /// The number of unprivileged registers
        pub const UNPRIV_REGS: usize = 6;
    }
    else {
        /// The number of external registers
        pub const EXT_REGS: usize = 5;
        /// The number of unprivileged registers
        pub const UNPRIV_REGS: usize = 6;
    }
}
cfg_if! {
    if #[cfg(any(feature = "hw22", feature = "hw23"))] {
        /// The number of registers per EP
        pub const EP_REGS: usize = 3;

        /// Represents unlimited credits for send EPs
        pub const UNLIM_CREDITS: u32 = 0x3F;

        /// The size of the TCU's MMIO area
        pub const MMIO_SIZE: usize = cfg::PAGE_SIZE * 2;
        /// The base address of the TCU's privileged MMIO area
        pub const MMIO_PRIV_ADDR: VirtAddr =
            VirtAddr::new(MMIO_ADDR.as_raw() + (cfg::PAGE_SIZE * 2) as VirtAddrRaw);
        /// The base address of the TCU's endpoint MMIO area
        pub const MMIO_EPS_ADDR: VirtAddr = VirtAddr::new(
            MMIO_ADDR.as_raw() +
                ((EXT_REGS + UNPRIV_REGS) * mem::size_of::<Reg>()) as VirtAddrRaw
        );
    }
    else {
        /// The number of registers per EP
        pub const EP_REGS: usize = 4;

        /// Represents unlimited credits for send EPs
        pub const UNLIM_CREDITS: u32 = 0x7F;

        /// The size of the TCU's MMIO area
        pub const MMIO_SIZE: usize = cfg::PAGE_SIZE;
        /// The base address of the TCU's privileged MMIO area
        pub const MMIO_PRIV_ADDR: VirtAddr =
            VirtAddr::new(MMIO_ADDR.as_raw() + MMIO_SIZE as VirtAddrRaw);
        /// The base address of the TCU's endpoint MMIO area
        pub const MMIO_EPS_ADDR: VirtAddr =
            VirtAddr::new(MMIO_PRIV_ADDR.as_raw() + MMIO_PRIV_SIZE as VirtAddrRaw);
    }
}

cfg_if! {
    if #[cfg(feature = "hw22")] {
        /// The external registers
        #[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive)]
        #[repr(u64)]
        pub enum ExtReg {
            /// Stores the privileged flag (for now)
            Features,
            /// For external commands
            ExtCmd,
        }
    }
    else if #[cfg(feature = "hw23")] {
        /// The external registers
        #[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive)]
        #[repr(u64)]
        pub enum ExtReg {
            /// Stores the privileged flag (for now)
            Features,
            /// Stores the tile description
            TileDesc,
            /// For external commands
            ExtCmd,
        }
    }
    else {
        /// The external registers
        #[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive)]
        #[repr(u64)]
        pub enum ExtReg {
            /// Stores the privileged flag (for now)
            Features,
            /// Stores the tile description
            TileDesc,
            /// For external commands
            ExtCmd,
            /// The global address of the EP region
            EpsAddr,
            /// The size of the EP region in bytes
            EpsSize,
        }
    }
}

bitflags! {
    /// The status flag for the [`ExtReg::Features`] register
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct FeatureFlags : Reg {
        /// Whether the tile is privileged
        const PRIV          = 1 << 0;
    }
}

cfg_if! {
    if #[cfg(feature = "hw22")] {
        const CU_REQ_TYPE_MASK: Reg = 0x3;

        #[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive)]
        #[repr(u64)]
        /// The privileged registers
        pub enum PrivReg {
            /// For CU requests
            CUReq,
            /// For privileged commands
            PrivCmd,
            /// The argument for privileged commands
            PrivCmdArg,
            /// The current activity
            CurAct,
        }
    }
    else {
        const CU_REQ_TYPE_MASK: Reg = 0x7;

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
    }
}

cfg_if! {
    if #[cfg(feature = "hw22")] {
        /// The unprivileged registers
        #[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive)]
        #[repr(u64)]
        pub enum UnprivReg {
            /// Starts commands and signals their completion
            Command,
            /// Specifies the data address and size
            Data,
            /// Specifies an additional argument
            Arg1,
            /// The current time in nanoseconds
            CurTime,
            /// Prints a line into the gem5 log
            Print,
        }
    }
    else {
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
    }
}

/// The config registers (hardware only)
#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive)]
#[repr(u64)]
pub enum ConfigReg {
    /// Enables/disables the instruction trace
    InstrTrace = 0xD,
}

/// The different endpoint types
#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive)]
#[repr(u64)]
pub enum EpType {
    /// Invalid endpoint (unusable)
    Invalid,
    /// Send endpoint
    Send,
    /// Receive endpoint
    Receive,
    /// Memory endpoint
    Memory,
}

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
    /// Puts the CU to sleep
    Sleep,
}

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

/// The external commands
#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive)]
#[repr(u64)]
pub enum ExtCmdOpCode {
    /// The idle command has no effect
    Idle,
    /// Invalidate and endpoint, if possible
    InvEP,
    /// Reset the CU
    Reset,
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
    fn new_foreign_receive(req: Reg) -> Self {
        Self::ForeignReceive {
            act: (req >> 48) as u16,
            #[cfg(feature = "hw22")]
            ep: ((req >> 2) & 0xFFFF) as EpId,
            #[cfg(not(feature = "hw22"))]
            ep: ((req >> 3) & 0xFFFF) as EpId,
        }
    }

    fn new_pmp_failure(req: Reg) -> Self {
        Self::PMPFailure {
            phys: (req >> 32) as u32,
            write: ((req >> 3) & 0x1) != 0,
            error: Code::from(((req >> 4) & 0x1ffff) as u32),
        }
    }
}

bitflags! {
    struct PrivCtrl : Reg {
        /// If enabled, the TCU reports PMP failures as CU requests
        const PMP_FAILURES = 0x1;
    }
}

/// The TCU header
#[repr(C, packed)]
#[derive(Copy, Clone, Default, Debug)]
pub struct Header {
    other: u32,
    sender_ep: u16,
    reply_ep: u16,
    reply_label: Label,
    label: Label,
    #[cfg(not(feature = "hw22"))]
    _pad: u64,
}

impl Header {
    /// Returns the length of the message payload in bytes
    pub fn length(&self) -> usize {
        (self.other >> 19) as usize & ((1 << 13) - 1)
    }

    /// Returns the label that has been assigned to the sender of the message
    pub fn label(&self) -> Label {
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
        #[cfg(any(feature = "hw22", feature = "hw23"))]
        let unread = Self::read_ep_reg(ep, 2) >> 32;
        #[cfg(not(any(feature = "hw22", feature = "hw23")))]
        let unread = Self::read_ep_reg(ep, 3);
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
        #[cfg(any(feature = "hw22", feature = "hw23"))]
        let cur = (r0 >> 19) & 0x3F;
        #[cfg(not(any(feature = "hw22", feature = "hw23")))]
        let cur = (r0 >> 19) & 0x7F;
        #[cfg(any(feature = "hw22", feature = "hw23"))]
        let max = (r0 >> 25) & 0x3F;
        #[cfg(not(any(feature = "hw22", feature = "hw23")))]
        let max = (r0 >> 26) & 0x7F;
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

    /// Waits until the current command is completed and returns the error, if any occurred
    #[inline(always)]
    pub fn get_error() -> Result<(), Error> {
        loop {
            let cmd = Self::read_unpriv_reg(UnprivReg::Command);
            if (cmd & 0xF) == CmdOpCode::Idle.into() {
                let err = (cmd >> 20) & 0x1F;
                return Result::from(Code::from(err as u32));
            }
        }
    }

    /// Returns the time in nanoseconds since boot
    #[inline(always)]
    pub(crate) fn nanotime() -> u64 {
        Self::read_unpriv_reg(UnprivReg::CurTime)
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
            UnprivReg::Command,
            Self::build_cmd(0, CmdOpCode::Sleep, ep as u64),
        );
        Self::get_error()
    }

    /// Drops all messages in the receive buffer of given receive EP that have the given label.
    pub fn drop_msgs_with(buf_addr: VirtAddr, ep: EpId, label: Label) {
        // we assume that the one that used the label can no longer send messages. thus, if there
        // are no messages yet, we are done.
        #[cfg(any(feature = "hw22", feature = "hw23"))]
        let unread = Self::read_ep_reg(ep, 3) >> 32;
        #[cfg(not(any(feature = "hw22", feature = "hw23")))]
        let unread = Self::read_ep_reg(ep, 3);
        if unread == 0 {
            return;
        }

        let r0 = Self::read_ep_reg(ep, 0);
        #[cfg(any(feature = "hw22", feature = "hw23"))]
        let buf_size = 1 << ((r0 >> 35) & 0x3F);
        #[cfg(not(any(feature = "hw22", feature = "hw23")))]
        let buf_size = 1 << ((r0 >> 35) & 0x7F);

        #[cfg(any(feature = "hw22", feature = "hw23"))]
        let msg_size = (r0 >> 41) & 0x3F;
        #[cfg(not(any(feature = "hw22", feature = "hw23")))]
        let msg_size = (r0 >> 42) & 0x3F;
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
        #[cfg(any(feature = "hw22", feature = "hw23"))]
        let regs = EXT_REGS + UNPRIV_REGS + (128 * EP_REGS) as usize;
        #[cfg(not(any(feature = "hw22", feature = "hw23")))]
        let regs = EXT_REGS + UNPRIV_REGS;

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

    /// Fetches and thereby acknowledges the currently handled IRQ.
    ///
    /// This notifies the TCU that the next IRQ can be triggered, if any.
    pub fn fetch_irq() -> Result<IRQ, Error> {
        Self::write_priv_reg(PrivReg::PrivCmd, PrivCmdOpCode::FetchIRQ as Reg);
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
        #[cfg(not(feature = "hw22"))]
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
        Self::write_priv_reg(PrivReg::PrivCmd, PrivCmdOpCode::AbortCmd.into());

        loop {
            let cmd = Self::read_priv_reg(PrivReg::PrivCmd);
            if (cmd & 0xF) == PrivCmdOpCode::Idle.into() {
                let err = (cmd >> 4) & 0x1F;
                if err != 0 {
                    break Err(Error::new(Code::from(err as u32)));
                }
                else if (cmd >> 9) == 0 {
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
            PrivCmdOpCode::XchgAct as Reg | (nact << 9),
        );
        Self::get_priv_error()?;
        Ok(Self::read_priv_reg(PrivReg::PrivCmdArg))
    }

    /// Invalidates the TCU's TLB
    pub fn invalidate_tlb() {
        Self::write_priv_reg(PrivReg::PrivCmd, PrivCmdOpCode::InvTLB.into());
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
        #[cfg(feature = "hw22")]
        let val = ((asid as Reg) << 41)
            | ((virt.as_local() as Reg) << 9)
            | (PrivCmdOpCode::InvPage as Reg);
        #[cfg(not(feature = "hw22"))]
        let val = {
            Self::write_priv_reg(PrivReg::PrivCmdArg, virt.as_local() as Reg);
            ((asid as Reg) << 9) | (PrivCmdOpCode::InvPage as Reg)
        };

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
        #[cfg(feature = "hw22")]
        let tlb_flags = flags.bits() as Reg;
        #[cfg(not(feature = "hw22"))]
        let tlb_flags = {
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
            tlb_flags
        };

        let phys = if flags.contains(PageFlags::L) {
            // the current TCU's TLB does not support large pages
            phys.as_raw() | (virt.as_local() & cfg::LPAGE_MASK & !cfg::PAGE_MASK) as PhysAddrRaw
        }
        else {
            phys.as_raw()
        };

        #[cfg(feature = "hw22")]
        let (arg_addr, cmd_addr) = (phys, virt.as_local());
        #[cfg(not(feature = "hw22"))]
        let (arg_addr, cmd_addr) = (virt.as_local(), phys);

        Self::write_priv_reg(PrivReg::PrivCmdArg, arg_addr as Reg);
        CPU::memory_barrier();
        let cmd = ((asid as Reg) << 41)
            | (((cmd_addr as Reg) & !(cfg::PAGE_MASK as Reg)) << 9)
            | (tlb_flags << 9)
            | PrivCmdOpCode::InsTLB as Reg;
        Self::write_priv_reg(PrivReg::PrivCmd, cmd);
        Self::get_priv_error()
    }

    /// Sets the timer to fire in `delay_ns` nanoseconds if `delay_ns` is nonzero. Otherwise, unsets
    /// the timer.
    pub fn set_timer(delay_ns: u64) -> Result<(), Error> {
        Self::write_priv_reg(
            PrivReg::PrivCmd,
            PrivCmdOpCode::SetTimer as Reg | (delay_ns << 9),
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
            let cmd = Self::read_priv_reg(PrivReg::PrivCmd);
            if (cmd & 0xF) == PrivCmdOpCode::Idle.into() {
                return Code::from(((cmd >> 4) & 0x1F) as u32);
            }
        }
    }

    /// Enables or disables instruction tracing
    pub fn set_trace_instrs(enable: bool) {
        Self::write_cfg_reg(ConfigReg::InstrTrace, enable as Reg);
    }

    pub fn mmio_areas() -> [(VirtAddr, usize, PageFlags); 3] {
        #[cfg(any(feature = "hw22", feature = "hw23"))]
        return [
            (MMIO_ADDR, cfg::PAGE_SIZE * 2, PageFlags::U | PageFlags::RW),
            (
                MMIO_PRIV_ADDR,
                cfg::PAGE_SIZE * 2,
                PageFlags::U | PageFlags::RW,
            ),
            (VirtAddr::null(), 0, PageFlags::empty()),
        ];
        #[cfg(not(any(feature = "hw22", feature = "hw23")))]
        return [
            (MMIO_ADDR, MMIO_SIZE, PageFlags::U | PageFlags::RW),
            (MMIO_PRIV_ADDR, MMIO_PRIV_SIZE, PageFlags::U | PageFlags::RW),
            (
                MMIO_EPS_ADDR,
                Self::endpoints_size(),
                PageFlags::U | PageFlags::R,
            ),
        ];
    }

    /// Returns the size of the endpoints region (according to the EPS_SIZE register)
    pub fn endpoints_size() -> usize {
        #[cfg(any(feature = "hw22", feature = "hw23"))]
        return 128 * EP_REGS * mem::size_of::<Reg>();
        #[cfg(not(any(feature = "hw22", feature = "hw23")))]
        return Self::read_reg(ExtReg::EpsSize as usize) as usize;
    }

    /// Writes the given address and size into the Data register
    pub fn write_data(addr: VirtAddr, size: usize) {
        #[cfg(feature = "hw22")]
        Self::write_unpriv_reg(
            UnprivReg::Data,
            (size as Reg) << 32 | addr.as_local() as Reg,
        );
        #[cfg(not(feature = "hw22"))]
        {
            Self::write_unpriv_reg(UnprivReg::DataAddr, addr.as_local() as Reg);
            Self::write_unpriv_reg(UnprivReg::DataSize, size as Reg);
        }
    }

    /// Returns the contents of the Data register (address and size)
    pub fn read_data() -> (usize, usize) {
        #[cfg(feature = "hw22")]
        {
            let data = Self::read_unpriv_reg(UnprivReg::Data);
            ((data & 0xFFFF_FFFF) as usize, (data >> 32) as usize)
        }
        #[cfg(not(feature = "hw22"))]
        {
            (
                Self::read_unpriv_reg(UnprivReg::DataAddr) as usize,
                Self::read_unpriv_reg(UnprivReg::DataSize) as usize,
            )
        }
    }

    /// Returns the value of the given unprivileged register
    pub fn read_unpriv_reg(reg: UnprivReg) -> Reg {
        Self::read_reg(EXT_REGS + reg as usize)
    }

    /// Sets the value of the given unprivileged register to `val`
    pub fn write_unpriv_reg(reg: UnprivReg, val: Reg) {
        Self::write_reg(EXT_REGS + reg as usize, val)
    }

    fn write_cfg_reg(reg: ConfigReg, val: Reg) {
        Self::write_reg(
            ((cfg::PAGE_SIZE * 3) / mem::size_of::<Reg>()) + reg as usize,
            val,
        )
    }

    fn read_ep_reg(ep: EpId, reg: usize) -> Reg {
        Self::read_reg(
            (MMIO_EPS_ADDR.as_local() - MMIO_ADDR.as_local()) / mem::size_of::<Reg>()
                + EP_REGS * ep as usize
                + reg,
        )
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

    fn read_reg(idx: usize) -> Reg {
        // safety: we know that the address is within the MMIO region of the TCU
        unsafe { CPU::read8b((MMIO_ADDR.as_ptr::<Reg>()).add(idx)) }
    }

    fn write_reg(idx: usize, val: Reg) {
        // safety: as above
        unsafe { CPU::write8b((MMIO_ADDR.as_mut_ptr::<Reg>()).add(idx), val) };
    }

    fn build_cmd(ep: EpId, cmd: CmdOpCode, arg: Reg) -> Reg {
        cmd as Reg | ((ep as Reg) << 4) | (arg << 25)
    }
}

static TILE_IDS: LazyReadOnlyCell<[u16; cfg::MAX_TILES * cfg::MAX_CHIPS]> =
    LazyReadOnlyCell::default();

impl TCU {
    #[cold]
    fn init_tileid_translation() {
        let mut ids = [0u16; cfg::MAX_TILES * cfg::MAX_CHIPS];

        let mut log_chip = 0;
        let mut log_tile = 0;
        let mut phys_chip = None;
        assert!(env::boot().raw_tile_count > 0);
        for id in &env::boot().raw_tile_ids[0..env::boot().raw_tile_count as usize] {
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
        }

        TILE_IDS.set(ids);
    }

    #[inline]
    pub fn tileid_to_nocid(tile: TileId) -> u16 {
        if !TILE_IDS.is_some() {
            Self::init_tileid_translation();
        }

        TILE_IDS.get()[tile.chip() as usize * cfg::MAX_TILES + tile.tile() as usize]
    }

    #[inline]
    pub fn nocid_to_tileid(tile: u16) -> TileId {
        if !TILE_IDS.is_some() {
            Self::init_tileid_translation();
        }

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
        buf: PhysAddr,
        buf_ord: u32,
        msg_ord: u32,
        reply_eps: Option<EpId>,
    ) {
        #[cfg(any(feature = "hw22", feature = "hw23"))]
        {
            regs[0] = (EpType::Receive as Reg)
                | ((act as Reg) << 3)
                | ((reply_eps.unwrap_or(NO_REPLIES) as Reg) << 19)
                | (((buf_ord - msg_ord) as Reg) << 35)
                | ((msg_ord as Reg) << 41);
            regs[1] = buf.as_raw() as Reg;
            regs[2] = 0;
        }
        #[cfg(not(any(feature = "hw22", feature = "hw23")))]
        {
            regs[0] = (EpType::Receive as Reg)
                | ((act as Reg) << 3)
                | ((reply_eps.unwrap_or(NO_REPLIES) as Reg) << 19)
                | (((buf_ord - msg_ord) as Reg) << 35)
                | ((msg_ord as Reg) << 42);
            regs[1] = buf.as_raw() as Reg;
            regs[2] = 0;
            regs[3] = 0;
        }
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
        #[cfg(any(feature = "hw22", feature = "hw23"))]
        {
            regs[0] = (EpType::Send as Reg)
                | ((act as Reg) << 3)
                | ((credits as Reg) << 19)
                | ((credits as Reg) << 25)
                | ((msg_order as Reg) << 31);
            regs[1] = (dst_ep as Reg) | ((Self::tileid_to_nocid(tile) as Reg) << 16);
            regs[2] = lbl as Reg;
        }
        #[cfg(not(any(feature = "hw22", feature = "hw23")))]
        {
            regs[0] = (EpType::Send as Reg)
                | ((act as Reg) << 3)
                | ((credits as Reg) << 19)
                | ((credits as Reg) << 26)
                | ((msg_order as Reg) << 33);
            regs[1] = (dst_ep as Reg) | ((Self::tileid_to_nocid(tile) as Reg) << 16);
            regs[2] = lbl as Reg;
            regs[3] = 0;
        }
    }

    pub fn config_mem(
        regs: &mut [Reg],
        act: ActId,
        tile: TileId,
        addr: GlobOff,
        size: usize,
        perm: Perm,
    ) {
        regs[0] = (EpType::Memory as Reg)
            | ((act as Reg) << 3)
            | ((perm.bits() as Reg) << 19)
            | ((Self::tileid_to_nocid(tile) as Reg) << 23);
        regs[1] = addr as Reg;
        regs[2] = size as Reg;
        #[cfg(not(any(feature = "hw22", feature = "hw23")))]
        {
            regs[3] = 0;
        }
    }

    /// Configures the given endpoint
    pub fn set_ep_regs(ep: EpId, regs: &[Reg]) {
        let off = EP_REGS * ep as usize;
        unsafe {
            let addr = (MMIO_EPS_ADDR.as_mut_ptr::<Reg>()).add(off);
            for (i, r) in regs.iter().enumerate() {
                CPU::write8b(addr.add(i), *r);
            }
        }
        // ensure that all accesses are finished before we try to use the EP
        CPU::memory_barrier();
    }

    /// Returns the MMIO address for the given external register
    pub fn ext_reg_addr(reg: ExtReg) -> VirtAddr {
        MMIO_ADDR + (reg as usize) * mem::size_of::<Reg>()
    }

    /// Returns the MMIO address of the given endpoint registers
    pub fn ep_regs_addr(ep: EpId) -> VirtAddr {
        MMIO_EPS_ADDR + (EP_REGS * ep as usize) * mem::size_of::<Reg>()
    }
}

