/*
 * Copyright (C) 2021-2022 Nils Asmussen, Barkhausen Institut
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

#[allow(unused_extern_crates)]
extern crate heap;

#[path = "../../vmtest/src/helper.rs"]
mod helper;
#[path = "../../vmtest/src/paging.rs"]
mod paging;

use base::cell::StaticRefCell;
use base::mem::{AlignedBuf, VirtAddr};
use base::tcu::{self, EpId, TCU};
use base::util::math;

const OWN_ACT: u16 = 0xFFFF;
const CREDITS: usize = 16;
const CLIENTS: usize = 2;
const MSG_SIZE: usize = 64;

const REP: EpId = tcu::FIRST_USER_EP;
const RPLEPS: EpId = tcu::FIRST_USER_EP + 1;

static RBUF: [u64; CREDITS * CLIENTS * MSG_SIZE] = [0; CREDITS * CLIENTS * MSG_SIZE];
static SBUF: StaticRefCell<AlignedBuf<2048>> = StaticRefCell::new(AlignedBuf::new_zeroed());

#[no_mangle]
pub extern "C" fn env_run() {
    helper::init("stdareceiver");

    let buf_ord = math::next_log2(RBUF.len());
    let msg_ord = buf_ord - math::next_log2(CLIENTS * CREDITS);
    let (rbuf_virt, rbuf_phys) = helper::virt_to_phys(VirtAddr::from(RBUF.as_ptr()));
    helper::config_local_ep(REP, |regs| {
        TCU::config_recv(regs, OWN_ACT, rbuf_phys, buf_ord, msg_ord, Some(RPLEPS));
    });

    loop {
        let rmsg = loop {
            if let Some(m) = helper::fetch_msg(REP, rbuf_virt) {
                break m;
            }
        };
        TCU::reply_aligned(
            REP,
            SBUF.borrow().as_ptr(),
            1,
            TCU::msg_to_offset(rbuf_virt, rmsg),
        )
        .unwrap();
    }
}
