/*
 * Copyright (C) 2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019-2020 Nils Asmussen, Barkhausen Institut
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

use m3::com::{EpMng, RecvCap, RecvGate, EP};
use m3::errors::{Code, Error};
use m3::mem::{VirtAddr, VirtAddrRaw};
use m3::tcu::EpId;
use m3::tiles::ChildActivity;
use m3::util::math::next_log2;
use m3::vfs::{File, FileRef, GenericFile};

const MSG_SIZE: usize = 64;
const RB_SIZE: usize = MSG_SIZE * 4;

const EP_IN_SEND: EpId = 16;
const EP_IN_MEM: EpId = 17;
const EP_OUT_SEND: EpId = 18;
const EP_OUT_MEM: EpId = 19;
const EP_RECV: EpId = 20;

pub struct StreamAccel {
    _rgate: RecvGate,
    in_sep: Option<EP>,
    in_mep: EP,
    out_sep: Option<EP>,
    out_mep: EP,
}

impl StreamAccel {
    pub fn new(act: &ChildActivity) -> Result<Self, Error> {
        let rcap = RecvCap::new(next_log2(RB_SIZE), next_log2(MSG_SIZE))?;
        let in_sep = Some(EpMng::acquire_for(act.sel(), EP_IN_SEND, 0)?);
        let in_mep = EpMng::acquire_for(act.sel(), EP_IN_MEM, 0)?;
        let out_sep = Some(EpMng::acquire_for(act.sel(), EP_OUT_SEND, 0)?);
        let out_mep = EpMng::acquire_for(act.sel(), EP_OUT_MEM, 0)?;
        let rep = EpMng::acquire_for(act.sel(), EP_RECV, RB_SIZE / MSG_SIZE)?;
        let recv_addr = VirtAddr::new(act.tile_desc().mem_offset() as VirtAddrRaw + 0x1_4C00);
        let _rgate = rcap.activate_with(None, recv_addr.as_goff(), recv_addr, Some(rep))?;
        Ok(Self {
            _rgate,
            in_sep,
            in_mep,
            out_sep,
            out_mep,
        })
    }

    pub fn attach_input(&mut self, file: &mut FileRef<GenericFile>) -> Result<(), Error> {
        file.attach(
            self.in_sep.take().ok_or_else(|| Error::new(Code::Exists))?,
            &self.in_mep,
        )
    }

    pub fn attach_output(&mut self, file: &mut FileRef<GenericFile>) -> Result<(), Error> {
        file.attach(
            self.out_sep
                .take()
                .ok_or_else(|| Error::new(Code::Exists))?,
            &self.out_mep,
        )
    }
}
