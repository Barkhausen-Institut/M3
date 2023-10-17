/*
 * Copyright (C) 2022 Nils Asmussen, Barkhausen Institut
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

use m3::cell::StaticRefCell;
use m3::col::Vec;
use m3::com::{RGateArgs, RecvGate, Semaphore, SendGate};
use m3::env;
use m3::errors::Code;
use m3::mem::AlignedBuf;
use m3::{format, println, wv_assert_ok};

static BUF: StaticRefCell<AlignedBuf<2048>> = StaticRefCell::new(AlignedBuf::new_zeroed());

#[no_mangle]
pub fn main() -> i32 {
    let args = env::args().collect::<Vec<_>>();
    let prio = args[1].parse::<u64>().expect("Unable to parse priority");

    let sgate = wv_assert_ok!(SendGate::new_named(&format!("chan{}", prio)));
    wv_assert_ok!(sgate.activate());

    let mut reply_gate =
        RecvGate::new_with(RGateArgs::default().order(6 + 5).msg_order(6)).unwrap();
    wv_assert_ok!(reply_gate.activate());

    wv_assert_ok!(Semaphore::attach("ready").unwrap().down());

    loop {
        while let Some(msg) = reply_gate.fetch() {
            reply_gate.ack_msg(msg).unwrap();
        }

        let res = sgate.send_aligned(BUF.borrow().as_ptr(), 1, &reply_gate);
        match res {
            Ok(_) => {},
            Err(e)
                if e.code() == Code::RecvNoSpace
                    || e.code() == Code::RecvGone
                    || e.code() == Code::NoCredits => {},
            Err(e) => println!("Unexpected error {}", e),
        }
    }
}
