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

use core::fmt;
use core::ops;

use crate::cap::Capability;
use crate::cap::{CapFlags, SelSpace, Selector};
use crate::cell::{Cell, LazyReadOnlyCell};
use crate::cfg;
use crate::com::rbufs::{alloc_rbuf, free_rbuf};
use crate::com::{gate::Gate, EpMng, GateCap, RecvBuf, SendGate, EP};
use crate::env;
use crate::errors::{Code, Error};
use crate::kif::INVALID_SEL;
use crate::mem::{GlobOff, MsgBuf, VirtAddr};
use crate::syscalls;
use crate::tcu;
use crate::tiles::{Activity, OwnActivity};
use crate::util::math;

const DEF_MSG_ORD: u32 = 6;

static SYS_RGATE: LazyReadOnlyCell<RecvGate> = LazyReadOnlyCell::default();
static UPC_RGATE: LazyReadOnlyCell<RecvGate> = LazyReadOnlyCell::default();
static DEF_RGATE: LazyReadOnlyCell<RecvGate> = LazyReadOnlyCell::default();

/// The arguments for [`RecvGate`] creations
pub struct RGateArgs {
    order: u32,
    msg_order: u32,
    sel: Selector,
    flags: CapFlags,
}

impl Default for RGateArgs {
    fn default() -> Self {
        RGateArgs {
            order: DEF_MSG_ORD,
            msg_order: DEF_MSG_ORD,
            sel: INVALID_SEL,
            flags: CapFlags::empty(),
        }
    }
}

impl RGateArgs {
    /// Sets the size of the receive buffer as a power of two. That is, the size in bytes is
    /// `2^order`. This overwrites the default size of 64 bytes.
    pub fn order(mut self, order: u32) -> Self {
        self.order = order;
        self
    }

    /// Sets the size of message slots in the receive buffer as a power of two. That is, the size in
    /// bytes is `2^order`. This overwrites the default size of 64 bytes.
    pub fn msg_order(mut self, msg_order: u32) -> Self {
        self.msg_order = msg_order;
        self
    }

    /// Sets the capability selector to use for the `RecvGate`. Otherwise and by default,
    /// [`SelSpace::get().alloc_sel`](crate::cap::SelSpace::alloc_sel) will be used.
    pub fn sel(mut self, sel: Selector) -> Self {
        self.sel = sel;
        self
    }

    /// Sets the flags to `flags`.
    pub fn flags(mut self, flags: CapFlags) -> Self {
        self.flags = flags;
        self
    }
}

/// Represents a gate that can receive
///
/// This trait exists to support both `RecvCap` and `RecvGate` when creating `SendGate`s.
pub trait ReceivingGate {
    /// Returns the selector of the gate
    fn sel(&self) -> Selector;
}

/// A receive capability is the precursor of a `RecvGate`
///
/// `RecvCap` implements `GateCap` and can therefore be turned into a `RecvGate` through activation.
pub struct RecvCap {
    cap: Capability,
    order: Cell<Option<u32>>,
    msg_order: Cell<Option<u32>>,
}

impl RecvCap {
    /// Creates a new `RecvCap` with a `2^order` bytes receive buffer and `2^msg_order`
    /// bytes message slots.
    pub fn new(order: u32, msg_order: u32) -> Result<Self, Error> {
        Self::new_with(RGateArgs::default().order(order).msg_order(msg_order))
    }

    /// Creates a new `RecvCap` with given arguments.
    pub fn new_with(args: RGateArgs) -> Result<Self, Error> {
        let sel = if args.sel == INVALID_SEL {
            SelSpace::get().alloc_sel()
        }
        else {
            args.sel
        };

        syscalls::create_rgate(sel, args.order, args.msg_order)?;
        Ok(Self {
            cap: Capability::new(sel, args.flags),
            order: Cell::new(Some(args.order)),
            msg_order: Cell::new(Some(args.msg_order)),
        })
    }

    /// Creates the `RecvCap` with given name as defined in the application's configuration
    pub fn new_named(name: &str) -> Result<Self, Error> {
        let sel = SelSpace::get().alloc_sel();
        let (order, msg_order) = Activity::own().resmng().unwrap().use_rgate(sel, name)?;
        Ok(Self {
            cap: Capability::new(sel, CapFlags::empty()),
            order: Cell::new(Some(order)),
            msg_order: Cell::new(Some(msg_order)),
        })
    }

    /// Creates a `RecvCap` bound to given selector
    pub fn new_bind(sel: Selector) -> Self {
        Self {
            cap: Capability::new(sel, CapFlags::KEEP_CAP),
            order: Cell::new(None),
            msg_order: Cell::new(None),
        }
    }

    fn fetch_buffer_size(&self) -> Result<(), Error> {
        if self.msg_order.get().is_none() {
            let (order, msg_order) = syscalls::rgate_buffer(self.sel())?;
            self.order.replace(Some(order));
            self.msg_order.replace(Some(msg_order));
        }
        Ok(())
    }

    pub fn sel(&self) -> Selector {
        self.cap.sel()
    }

    /// Returns the size of the receive buffer in bytes
    pub fn size(&self) -> Result<usize, Error> {
        self.fetch_buffer_size()?;
        Ok(1 << self.order.get().unwrap())
    }

    /// Returns the maximum message size
    pub fn max_msg_size(&self) -> Result<usize, Error> {
        self.fetch_buffer_size()?;
        Ok(1 << self.msg_order.get().unwrap())
    }

    /// Activates this receive gate with given receive buffer
    #[cold]
    pub fn activate_with(
        mut self,
        mem: Option<Selector>,
        off: GlobOff,
        addr: VirtAddr,
        ep: Option<EP>,
    ) -> Result<RecvGate, Error> {
        self.fetch_buffer_size()?;

        let (order, msg_order) = (self.order.get().unwrap(), self.msg_order.get().unwrap());
        let ep = match ep {
            Some(ep) => ep,
            None => {
                let replies = 1 << (order - msg_order);
                EpMng::get().acquire(replies)?
            },
        };

        let gate = Gate::new_rgate(self.sel(), self.cap.flags(), mem, off, ep)?;

        // prevent that we revoke the cap
        self.cap.set_flags(CapFlags::KEEP_CAP);

        Ok(RecvGate {
            gate,
            buf: RGateBuf::Manual(addr),
            order,
            msg_order,
        })
    }
}

impl GateCap for RecvCap {
    type Source = Selector;
    type Target = RecvGate;

    fn new_from_cap(sel: Selector) -> Self {
        Self::new_bind(sel)
    }

    #[cold]
    fn activate(mut self) -> Result<Self::Target, Error> {
        let size = self.size()?;
        let buf = alloc_rbuf(size)?;

        let (order, msg_order) = (self.order.get().unwrap(), self.msg_order.get().unwrap());
        let replies = 1 << (order - msg_order);
        let ep = EpMng::get().acquire(replies)?;
        let gate = Gate::new_rgate(self.sel(), self.cap.flags(), buf.mem(), buf.off(), ep)?;

        // prevent that we revoke the cap
        self.cap.set_flags(CapFlags::KEEP_CAP);

        Ok(Self::Target {
            gate,
            buf: RGateBuf::Allocated(buf),
            order,
            msg_order,
        })
    }
}

impl ReceivingGate for RecvCap {
    fn sel(&self) -> Selector {
        self.cap.sel()
    }
}

#[derive(Debug)]
enum RGateBuf {
    Allocated(RecvBuf),
    Manual(VirtAddr),
}

/// A receive gate receives messages via TCU
///
/// A [`RecvGate`] works in combination with [`SendGate`]s to form message passing channels. Such a
/// channel exists between a [`SendGate`] and [`RecvGate`] and allows to exchange messages, always
/// initiated by the [`SendGate`]. Upon receiving a message, the [`RecvGate`] can send a reply to
/// the message, though.
///
/// # Message passing basics
///
/// A [`SendGate`] is always connected to exactly one [`RecvGate`], whereas a [`RecvGate`] can
/// receive messages from multiple [`SendGate`]s. Each message consists of a header, provided by the
/// TCU, and a payload, provided by the sender. Thus, headers are trustworthy (we always trust the
/// TCU), whereas the payloads are not. The header contains meta data about the message such as its
/// length and a *label*. A label can be set for each [`SendGate`], which allows to distinguish
/// between senders. On the receiver side, messages are stored in a *receive buffer*. Hence, each
/// [`RecvGate`] has an associated receive buffer, represented by [`RecvBuf`].
///
/// # Receive buffer and credit system
///
/// The receive buffer is split into fixed-sized slots and shared among all senders, but each sender
/// has a certain number of *credits* that limits the available space for that sender. Messages can
/// be smaller than the slot size (to reduce traffic), but not larger. The credit system is
/// implemented by the TCU and requires senders to have at least one credit when sending a message.
/// If one credit is available, the number of credits is reduced by one. The number of credits is
/// increased again upon a reply from the receiver. If at most as many credits as receive-buffer
/// slots are handed out to senders, each sender has the guarantee that message sending will always
/// succeed. Otherwise, senders receive the [`RecvNoSpace`](`Code::RecvNoSpace`) error in case all
/// slots are occupied.
///
/// # Receive buffer slots
///
/// To keep track of the receive buffer slots, slots can be in three states: `free`, `unread`, and
/// `occupied`. Free slots are filled by the TCU upon message reception, which brings the slot into
/// the `unread` state. Thus, unread slots contain new messages (not seen by the software). These
/// messages can be *fetched* from the receive buffer via [`RecvGate::fetch`], which brings the slot
/// into the `occupied` state. As soon as the message has been processed, the software should inform
/// the TCU about that by *acknowledging* the message via [`RecvGate::ack_msg`], which brings the
/// slot back into the `free` state.
///
/// # Message reception and processing
///
/// The TCU stores received messages into the next slot that is `free` by walking over the slots in
/// round-robin fashion and remembering the last used slot (to prevent starvation). New messages are
/// retrieved via [`RecvGate::fetch`] in non-blocking fashion or [`RecvGate::receive`] in blocking
/// fashion. Note also that this allows to reply to messages out of order. That is, it is possible
/// to receive message A first and then message B, but first reply to message B and later to message
/// A.
///
/// Messages are implicitly acknowledged when replying to the message (see [`RecvGate::reply`]), but
/// need to be acknowledged explicitly otherwise (see [`RecvGate::ack_msg`]).
///
/// # Activation
///
/// Activation is the process of turning a receive capability into a usable receive gate for
/// receiving messages via TCU. Thus, activation allocates and configures a TCU endpoint. A
/// `RecvGate` is always activated from the start, whereas `RecvCap` is only the capability that can
/// be turned into a `RecvGate` by activating it. If you want to receive messages yourself, you can
/// simply create a new `RecvGate`. However, if you want someone else to receive messages, you
/// should create a `RecvCap` and delegate it to the desired activity, which can then turn it into a
/// `RecvGate`.
pub struct RecvGate {
    gate: Gate,
    buf: RGateBuf,
    order: u32,
    msg_order: u32,
}

impl fmt::Debug for RecvGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "RecvGate[sel: {}, buf: {:?}, size: {}, ep: {}]",
            self.sel(),
            self.buf,
            1 << self.order,
            self.ep()
        )
    }
}

impl RecvGate {
    /// Returns the receive gate to receive system call replies
    pub fn syscall() -> &'static RecvGate {
        SYS_RGATE.get()
    }

    /// Returns the receive gate to receive upcalls from the kernel
    pub fn upcall() -> &'static RecvGate {
        UPC_RGATE.get()
    }

    /// Returns the default receive gate
    pub fn def() -> &'static RecvGate {
        DEF_RGATE.get()
    }

    const fn new_def(sel: Selector, ep: tcu::EpId, addr: VirtAddr, order: u32) -> Self {
        RecvGate {
            gate: Gate::new_with_ep(sel, CapFlags::KEEP_CAP, EP::new_def_bind(ep)),
            buf: RGateBuf::Manual(addr),
            order,
            msg_order: order,
        }
    }

    /// Creates a new `RecvGate` with a `2^order` bytes receive buffer and `2^msg_order` bytes
    /// message slots.
    pub fn new(order: u32, msg_order: u32) -> Result<Self, Error> {
        Self::new_with(RGateArgs::default().order(order).msg_order(msg_order))
    }

    /// Creates a new `RecvGate` with given arguments.
    pub fn new_with(args: RGateArgs) -> Result<Self, Error> {
        RecvCap::new_with(args)?.activate()
    }

    /// Creates the `RecvGate` with given name as defined in the application's configuration
    pub fn new_named(name: &str) -> Result<Self, Error> {
        RecvCap::new_named(name)?.activate()
    }

    /// Binds a new `RecvGate` to the given selector.
    pub fn new_bind(sel: Selector) -> Result<Self, Error> {
        RecvCap::new_bind(sel).activate()
    }

    pub fn sel(&self) -> Selector {
        self.gate.sel()
    }

    /// Returns the endpoint of the gate
    pub(crate) fn ep(&self) -> tcu::EpId {
        self.gate.ep().id()
    }

    /// Returns the size of the receive buffer in bytes
    pub fn size(&self) -> usize {
        1 << self.order
    }

    /// Returns the maximum message size
    pub fn max_msg_size(&self) -> usize {
        1 << self.msg_order
    }

    /// Returns the address of the receive buffer
    #[inline(always)]
    pub fn address(&self) -> VirtAddr {
        match self.buf {
            RGateBuf::Manual(addr) => addr,
            RGateBuf::Allocated(ref buf) => buf.addr(),
        }
    }

    /// Returns true if there are messages that can be fetched
    #[inline(always)]
    pub fn has_msgs(&self) -> bool {
        tcu::TCU::has_msgs(self.ep())
    }

    /// Tries to fetch a message from the receive gate. If there is an unread message, it returns
    /// a reference to the message. Otherwise it returns an error with [`Code::NotFound`].
    #[inline(always)]
    pub fn fetch(&self) -> Result<&'static tcu::Message, Error> {
        tcu::TCU::fetch_msg(self.ep())
            .map(|off| tcu::TCU::offset_to_msg(self.address(), off))
            .ok_or_else(|| Error::new(Code::NotFound))
    }

    /// Sends `reply` as a reply to the message `msg`.
    #[inline(always)]
    pub fn reply(&self, reply: &MsgBuf, msg: &'static tcu::Message) -> Result<(), Error> {
        let off = tcu::TCU::msg_to_offset(self.address(), msg);
        tcu::TCU::reply(self.ep(), reply, off)
    }

    /// Sends `reply` as a reply to the message `msg`. The message address needs to be 16-byte
    /// aligned and `reply`..`reply` + `len` cannot contain a page boundary.
    #[inline(always)]
    pub fn reply_aligned(
        &self,
        reply: *const u8,
        len: usize,
        msg: &'static tcu::Message,
    ) -> Result<(), Error> {
        let off = tcu::TCU::msg_to_offset(self.address(), msg);
        tcu::TCU::reply_aligned(self.ep(), reply, len, off)
    }

    /// Marks the given message as 'read', allowing the TCU to overwrite it with a new message.
    #[inline(always)]
    pub fn ack_msg(&self, msg: &tcu::Message) -> Result<(), Error> {
        let off = tcu::TCU::msg_to_offset(self.address(), msg);
        tcu::TCU::ack_msg(self.ep(), off)
    }

    /// Waits until a message arrives and returns a reference to the message.
    ///
    /// In contrast to [`RecvGate::fetch`], this method blocks until a message is received via this
    /// `RecvGate`. Depending on the platform and whether there are other activities ready to run on
    /// our tile, blocking will be performed via TCU (on gem5 and if no other activity is ready),
    /// polling (on hw and if no other activity is ready), or blocking of the activity (if another
    /// activity is ready).
    ///
    /// If not `None`, the argument `sgate` denotes the [`SendGate`] that was used to send the
    /// request to the communication partner for which this method should receive the reply now. If
    /// the endpoint associated with `sgate` becomes invalid, the method stops waiting for a reply
    /// assuming that the communication partner is no longer interested in the communication.
    #[inline(always)]
    pub fn receive(&self, sgate: Option<&SendGate>) -> Result<&'static tcu::Message, Error> {
        // if the tile is shared with someone else that wants to run, poll a couple of times to
        // prevent too frequent/unnecessary switches.
        let polling = if env::get().shared() { 200 } else { 1 };
        loop {
            for _ in 0..polling {
                let msg_off = tcu::TCU::fetch_msg(self.ep());
                if let Some(off) = msg_off {
                    let msg = tcu::TCU::offset_to_msg(self.address(), off);
                    return Ok(msg);
                }
            }

            if let Some(sg) = sgate {
                if !tcu::TCU::is_valid(sg.ep().id()) {
                    return Err(Error::new(Code::NoSEP));
                }
            }

            OwnActivity::wait_for(Some(self.ep()), None, None)?;
        }
    }

    /// Drops all messages with given label. That is, these messages will be marked as read.
    ///
    /// This may be required when clients are removed at the server side to ensure that no further
    /// messages from that client are already stored in the receive buffer. Note that the send EP of
    /// the client has to be invalidated *before* calling this method to ensure that no further
    /// message of the client can arrive.
    pub fn drop_msgs_with(&self, label: tcu::Label) {
        tcu::TCU::drop_msgs_with(self.address(), self.ep(), label);
    }
}

impl ReceivingGate for RecvGate {
    fn sel(&self) -> Selector {
        self.gate.sel()
    }
}

pub(crate) fn pre_init() {
    let eps_start = env::get().first_std_ep();
    let mut rbuf = env::get().tile_desc().rbuf_std_space().0;

    SYS_RGATE.set(RecvGate::new_def(
        INVALID_SEL,
        eps_start + tcu::SYSC_REP_OFF,
        rbuf,
        math::next_log2(cfg::SYSC_RBUF_SIZE),
    ));
    rbuf += cfg::SYSC_RBUF_SIZE;

    UPC_RGATE.set(RecvGate::new_def(
        INVALID_SEL,
        eps_start + tcu::UPCALL_REP_OFF,
        rbuf,
        math::next_log2(cfg::UPCALL_RBUF_SIZE),
    ));
    rbuf += cfg::UPCALL_RBUF_SIZE;

    DEF_RGATE.set(RecvGate::new_def(
        INVALID_SEL,
        eps_start + tcu::DEF_REP_OFF,
        rbuf,
        math::next_log2(cfg::DEF_RBUF_SIZE),
    ));
}

impl ops::Drop for RecvGate {
    fn drop(&mut self) {
        self.gate.release(true);
        if let RGateBuf::Allocated(ref b) = self.buf {
            free_rbuf(b);
        }
    }
}
