/*
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

use base::errors::Code;
use base::io::LogFlags;
use base::kif;
use base::log;
use base::tcu;

use crate::activities;

pub fn handle(req: tcu::CUReq) {
    match req {
        tcu::CUReq::ForeignReceive { act, ep } => handle_foreign_recv(act, ep),
        tcu::CUReq::PMPFailure { phys, write, error } => handle_pmp_failure(phys, write, error),
    }

    tcu::TCU::set_cu_resp();
}

fn handle_foreign_recv(act: u16, ep: tcu::EpId) {
    // add message to activity
    if let Some(mut v) = activities::get_mut(act as activities::Id) {
        // if this activity is currently running, we have to update the CUR_ACT register
        if (tcu::TCU::get_cur_activity() & 0xFFFF) == act as activities::Id {
            // temporary switch to idle
            let old_act = tcu::TCU::xchg_activity(activities::idle().activity_reg()).unwrap();
            // set user event
            v.set_activity_reg(old_act);
            v.add_msg();
            // switch back
            tcu::TCU::xchg_activity(v.activity_reg()).unwrap();
        }
        // otherwise, just add it to our copy of CUR_ACT
        else {
            v.add_msg();
        }

        log!(
            LogFlags::MuxForMsgs,
            "Added message to Activity {} ({} msgs)",
            act,
            v.msgs()
        );

        if v.id() != kif::tilemux::ACT_ID {
            v.unblock(activities::Event::Message(ep));
        }
    }
}

fn handle_pmp_failure(_phys: u32, _write: bool, _error: Code) {
    // log!(
    //     LogFlags::Error,
    //     "PMP {} access to physical address {:#x} failed: {:?}",
    //     write,
    //     phys,
    //     error
    // );
}
