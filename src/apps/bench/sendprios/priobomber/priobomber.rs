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
use m3::com::{RGateArgs, RecvGate, SendGate};
use m3::errors::{Code, Error};
use m3::mem::AlignedBuf;
use m3::{println, wv_assert_ok};

static BUF: StaticRefCell<AlignedBuf<2048>> = StaticRefCell::new(AlignedBuf::new_zeroed());

#[no_mangle]
pub fn main() -> Result<(), Error> {
    let sgate = wv_assert_ok!(SendGate::new_named("chan"));
    let reply_gate = RecvGate::new_with(RGateArgs::default().order(6 + 5).msg_order(6)).unwrap();

    loop {
        while let Ok(msg) = reply_gate.fetch() {
            reply_gate.ack_msg(msg).unwrap();
        }

        let res = sgate.send_aligned(BUF.borrow().as_ptr(), 1, &reply_gate);
        match res {
            Ok(_) => {},
            Err(e) if e.code() == Code::RecvNoSpace || e.code() == Code::RecvGone => {},
            Err(e) => println!("Unexpected error {}", e),
        }
    }
}
