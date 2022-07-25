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
use m3::com::{recv_msg, RecvGate, Semaphore};
use m3::env;
use m3::mem::AlignedBuf;

static BUF: StaticRefCell<AlignedBuf<2048>> = StaticRefCell::new(AlignedBuf::new_zeroed());

#[no_mangle]
pub fn main() -> i32 {
    let mut rgate = RecvGate::new_named("chan").expect("Unable to create receive gate");
    rgate.activate().expect("Unable to activate receive gate");

    let args = env::args().collect::<Vec<_>>();
    let runs = args[1]
        .parse::<u64>()
        .expect("Unable to parse number of runs argument");
    let msgsize = args[2]
        .parse::<usize>()
        .expect("Unable to parse message size argument");

    Semaphore::attach("ready").unwrap().up().unwrap();

    for _ in 0..runs {
        let mut msg = recv_msg(&rgate).unwrap();
        msg.reply_aligned(BUF.borrow().as_ptr(), msgsize).unwrap();
    }
    0
}
