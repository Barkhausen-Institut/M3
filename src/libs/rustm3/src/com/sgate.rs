/*
 * Copyright (C) 2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
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

use cap::{CapFlags, Selector};
use com::gate::Gate;
use com::RecvGate;
use core::fmt;
use dtu;
use errors::Error;
use kif::INVALID_SEL;
use syscalls;
use util;
use vpe;

pub struct SendGate {
    gate: Gate,
}

pub struct SGateArgs {
    rgate_sel: Selector,
    label: dtu::Label,
    credits: u64,
    sel: Selector,
    flags: CapFlags,
}

impl SGateArgs {
    pub fn new(rgate: &RecvGate) -> Self {
        SGateArgs {
            rgate_sel: rgate.sel(),
            label: 0,
            credits: 0,
            sel: INVALID_SEL,
            flags: CapFlags::empty(),
        }
    }

    pub fn credits(mut self, credits: u64) -> Self {
        self.credits = credits;
        self
    }

    pub fn label(mut self, label: dtu::Label) -> Self {
        self.label = label;
        self
    }

    pub fn sel(mut self, sel: Selector) -> Self {
        self.sel = sel;
        self
    }
}

impl SendGate {
    pub fn new(rgate: &RecvGate) -> Result<Self, Error> {
        Self::new_with(SGateArgs::new(rgate))
    }

    pub fn new_with(args: SGateArgs) -> Result<Self, Error> {
        let sel = if args.sel == INVALID_SEL {
            vpe::VPE::cur().alloc_sel()
        }
        else {
            args.sel
        };

        syscalls::create_sgate(sel, args.rgate_sel, args.label, args.credits)?;
        Ok(SendGate {
            gate: Gate::new(sel, args.flags),
        })
    }

    pub fn new_bind(sel: Selector) -> Self {
        SendGate {
            gate: Gate::new(sel, CapFlags::KEEP_CAP),
        }
    }

    pub fn sel(&self) -> Selector {
        self.gate.sel()
    }

    pub fn ep(&self) -> Option<dtu::EpId> {
        self.gate.ep()
    }

    pub fn rebind(&mut self, sel: Selector) -> Result<(), Error> {
        self.gate.rebind(sel)
    }

    pub fn activate_for(&self, ep: Selector) -> Result<(), Error> {
        syscalls::activate(ep, self.sel(), 0)
    }

    #[inline(always)]
    pub fn send<T>(&self, msg: &[T], reply_gate: &RecvGate) -> Result<(), Error> {
        self.send_bytes(msg.as_ptr() as *const u8, msg.len() * util::size_of::<T>(), reply_gate, 0)
    }
    pub fn send_with_rlabel<T>(&self, msg: &[T], reply_gate: &RecvGate,
                               rlabel: dtu::Label) -> Result<(), Error> {
        self.send_bytes(msg.as_ptr() as *const u8, msg.len() * util::size_of::<T>(), reply_gate, rlabel)
    }
    #[inline(always)]
    pub fn send_bytes(&self, msg: *const u8, size: usize, reply_gate: &RecvGate,
                      rlabel: dtu::Label) -> Result<(), Error> {
        let ep = self.gate.activate()?;
        dtu::DTU::send(ep, msg, size, rlabel, reply_gate.ep().unwrap())
    }
}

impl fmt::Debug for SendGate {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "SendGate[sel: {}, ep: {:?}]", self.sel(), self.gate.ep())
    }
}
