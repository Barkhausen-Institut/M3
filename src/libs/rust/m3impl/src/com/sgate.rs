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

use crate::cap::{CapFlags, Capability, SelSpace, Selector};
use crate::com::ep::EP;
use crate::com::gate::Gate;
use crate::com::{GateCap, ReceivingGate, RecvGate};
use crate::errors::Error;
use crate::kif::{INVALID_SEL, UNLIM_CREDITS};
use crate::mem::MsgBuf;
use crate::syscalls;
use crate::tcu;
use crate::tiles::Activity;

/// A send capability is the precursor of a `SendGate`
///
/// `SendCap` implements `GateCap` and can therefore be turned into a `SendGate` through activation.
#[derive(Debug)]
pub struct SendCap {
    cap: Capability,
}

impl SendCap {
    /// Creates a new `SendCap` that can send messages to `rgate`.
    pub fn new<R: ReceivingGate>(rgate: &R) -> Result<Self, Error> {
        Self::new_with(SGateArgs::new(rgate))
    }

    /// Creates a new `SendCap` with given arguments.
    pub fn new_with(args: SGateArgs) -> Result<Self, Error> {
        let sel = if args.sel == INVALID_SEL {
            SelSpace::get().alloc_sel()
        }
        else {
            args.sel
        };

        syscalls::create_sgate(sel, args.rgate_sel, args.label, args.credits)?;
        Ok(Self {
            cap: Capability::new(sel, args.flags),
        })
    }

    /// Creates the `SendCap` with given name as defined in the application's configuration
    pub fn new_named(name: &str) -> Result<Self, Error> {
        let sel = SelSpace::get().alloc_sel();
        Activity::own().resmng().unwrap().use_sgate(sel, name)?;
        Ok(Self {
            cap: Capability::new(sel, CapFlags::empty()),
        })
    }

    /// Creates a `SendCap` that is bound to given selector
    pub fn new_bind(sel: Selector) -> Self {
        Self {
            cap: Capability::new(sel, CapFlags::KEEP_CAP),
        }
    }

    /// Returns the capability selector.
    pub fn sel(&self) -> Selector {
        self.cap.sel()
    }

    /// Activates this capability on given endpoint and returns the resulting [`SendGate`]
    pub fn activate_on(self, ep: EP) -> Result<SendGate, Error> {
        self.do_activate_on(Some(ep))
    }

    fn do_activate_on(mut self, ep: Option<EP>) -> Result<SendGate, Error> {
        let gate = Gate::new(self.sel(), self.cap.flags(), ep)?;

        // prevent that we revoke the cap
        self.cap.set_flags(CapFlags::KEEP_CAP);

        Ok(SendGate { gate })
    }
}

impl GateCap for SendCap {
    type Source = Selector;
    type Target = SendGate;

    fn new_from_cap(src: Selector) -> Self {
        Self::new_bind(src)
    }

    fn activate(self) -> Result<Self::Target, Error> {
        self.do_activate_on(None)
    }
}

/// The arguments for [`SendGate`] creations.
pub struct SGateArgs {
    rgate_sel: Selector,
    label: tcu::Label,
    credits: u32,
    sel: Selector,
    flags: CapFlags,
}

impl SGateArgs {
    /// Creates a new `SGateArgs` to send messages to `rgate` with default settings.
    pub fn new<R: ReceivingGate>(rgate: &R) -> Self {
        SGateArgs {
            rgate_sel: rgate.sel(),
            label: 0,
            credits: UNLIM_CREDITS,
            sel: INVALID_SEL,
            flags: CapFlags::empty(),
        }
    }

    /// Sets the credits to `credits`.
    pub fn credits(mut self, credits: u32) -> Self {
        self.credits = credits;
        self
    }

    /// Sets the label to `label`.
    pub fn label(mut self, label: tcu::Label) -> Self {
        self.label = label;
        self
    }

    /// Sets the capability selector to use for the [`SendGate`]. Otherwise and by default,
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

/// A send gate sends message via TCU
///
/// The interaction of [`SendGate`]s and [`RecvGate`]s including the message-passing concept is
/// explained [`here`](`RecvGate`).
pub struct SendGate {
    gate: Gate,
}

impl SendGate {
    pub(crate) const fn new_def(sel: Selector, ep: tcu::EpId) -> Self {
        SendGate {
            gate: Gate::new_with_ep(sel, CapFlags::KEEP_CAP, EP::new_def_bind(ep)),
        }
    }

    /// Creates a new `SendGate` that can send messages to `rgate`.
    pub fn new<R: ReceivingGate>(rgate: &R) -> Result<Self, Error> {
        Self::new_with(SGateArgs::new(rgate))
    }

    /// Creates a new `SendGate` with given arguments.
    pub fn new_with(args: SGateArgs) -> Result<Self, Error> {
        SendCap::new_with(args)?.activate()
    }

    /// Creates the `SendGate` with given name as defined in the application's configuration
    pub fn new_named(name: &str) -> Result<Self, Error> {
        SendCap::new_named(name)?.activate()
    }

    /// Binds a new `SendGate` to the given capability selector.
    pub fn new_bind(sel: Selector) -> Result<Self, Error> {
        SendCap::new_bind(sel).activate()
    }

    /// Returns the capability selector.
    pub fn sel(&self) -> Selector {
        self.gate.sel()
    }

    /// Returns whether the TCU EP has credits to send a message
    pub fn can_send(&self) -> Result<bool, Error> {
        let ep = self.gate.ep().id();
        Ok(tcu::TCU::credits(ep)? > 0)
    }

    /// Returns the number of available credits
    pub fn credits(&self) -> Result<u32, Error> {
        let ep = self.gate.ep().id();
        tcu::TCU::credits(ep)
    }

    /// Returns the endpoint of the gate. If the gate is not activated, `None` is returned.
    pub(crate) fn ep(&self) -> &EP {
        self.gate.ep()
    }

    /// Sends `msg` to the associated [`RecvGate`] and uses `reply_gate` to receive
    /// a reply.
    #[inline(always)]
    pub fn send(&self, msg: &MsgBuf, reply_gate: &RecvGate) -> Result<(), Error> {
        self.send_with_rlabel(msg, reply_gate, 0)
    }

    /// Sends the message `msg` of `len` bytes via given endpoint. The message address needs to be
    /// 16-byte aligned and `msg`..`msg` + `len` cannot contain a page boundary.
    #[inline(always)]
    pub fn send_aligned(
        &self,
        msg: *const u8,
        len: usize,
        reply_gate: &RecvGate,
    ) -> Result<(), Error> {
        let ep = self.gate.ep().id();
        let rep = reply_gate.ep();
        tcu::TCU::send_aligned(ep, msg, len, 0, rep)
    }

    /// Sends `msg` to the associated [`RecvGate`], uses `reply_gate` to receive the reply, and lets
    /// the communication partner use the label `rlabel` for the reply.
    #[inline(always)]
    pub fn send_with_rlabel(
        &self,
        msg: &MsgBuf,
        reply_gate: &RecvGate,
        rlabel: tcu::Label,
    ) -> Result<(), Error> {
        let ep = self.gate.ep().id();
        let rep = reply_gate.ep();
        tcu::TCU::send(ep, msg, rlabel, rep)
    }

    /// Sends `msg` to the associated [`RecvGate`] and receives the reply from the set reply gate.
    /// Returns the received reply.
    #[inline(always)]
    pub fn call(
        &self,
        msg: &MsgBuf,
        reply_gate: &RecvGate,
    ) -> Result<&'static tcu::Message, Error> {
        let ep = self.gate.ep().id();
        let rep = reply_gate.ep();
        tcu::TCU::send(ep, msg, 0, rep)?;
        reply_gate.receive(Some(self))
    }
}

impl fmt::Debug for SendGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "SendGate[sel: {}, ep: {:?}]",
            self.sel(),
            self.gate.ep().id()
        )
    }
}
