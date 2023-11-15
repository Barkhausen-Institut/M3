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
use base::errors::Code;
use base::io::LogFlags;
use base::log;
use base::mem::{AlignedBuf, VirtAddr};
use base::tcu::{EpId, TileId, FIRST_USER_EP, TCU};
use base::util::math;

const OWN_ACT: u16 = 0xFFFF;

const DST_TILE: TileId = TileId::new(0, 0);
const DST_EP: EpId = FIRST_USER_EP;

const REP: EpId = FIRST_USER_EP;
const SEP: EpId = FIRST_USER_EP + 1;

const MSG_SIZE: usize = 64;

static RBUF: [u64; 32 * MSG_SIZE] = [0; 32 * MSG_SIZE];
static SBUF: StaticRefCell<AlignedBuf<2048>> = StaticRefCell::new(AlignedBuf::new_zeroed());

#[no_mangle]
pub extern "C" fn env_run() {
    helper::init("stdasender");

    let msg_size = math::next_log2(MSG_SIZE);
    helper::config_local_ep(SEP, |regs| {
        TCU::config_send(regs, OWN_ACT, 0x1234, DST_TILE, DST_EP, msg_size, 63);
    });

    let buf_ord = math::next_log2(RBUF.len());
    let msg_ord = math::next_log2(MSG_SIZE);
    let (rbuf_virt, rbuf_phys) = helper::virt_to_phys(VirtAddr::from(RBUF.as_ptr()));
    helper::config_local_ep(REP, |regs| {
        TCU::config_recv(regs, OWN_ACT, rbuf_phys, buf_ord, msg_ord, None);
    });

    loop {
        while let Some(m) = helper::fetch_msg(REP, rbuf_virt) {
            TCU::ack_msg(REP, TCU::msg_to_offset(rbuf_virt, m)).unwrap();
        }

        let res = TCU::send_aligned(SEP, SBUF.borrow().as_ptr(), 1, 0x2222, REP);
        match res {
            Ok(_) => {},
            Err(e) if e.code() == Code::RecvNoSpace || e.code() == Code::RecvGone => {},
            Err(e) => log!(LogFlags::Error, "Unexpected error {}", e),
        }
    }
}
