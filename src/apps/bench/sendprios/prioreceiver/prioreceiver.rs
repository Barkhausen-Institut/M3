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
use m3::com::{recv_msg, RecvGate};
use m3::errors::Error;
use m3::mem::AlignedBuf;

static BUF: StaticRefCell<AlignedBuf<2048>> = StaticRefCell::new(AlignedBuf::new_zeroed());

#[no_mangle]
pub fn main() -> Result<(), Error> {
    let rgate = RecvGate::new_named("chan").expect("Unable to create receive gate");

    loop {
        let mut msg = recv_msg(&rgate).unwrap();
        msg.reply_aligned(BUF.borrow().as_ptr(), 1).unwrap();
    }
}
