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
use m3::com::{GateIStream, RecvGate, Semaphore};
use m3::env;
use m3::format;
use m3::mem::AlignedBuf;
use m3::time::{TimeDuration, TimeInstant};

static BUF: StaticRefCell<AlignedBuf<2048>> = StaticRefCell::new(AlignedBuf::new_zeroed());

fn fetch_msg(gates: &Vec<RecvGate>) -> GateIStream<'_> {
    loop {
        for g in gates {
            if let Some(msg) = g.fetch() {
                return GateIStream::new(msg, g);
            }
        }
    }
}

#[no_mangle]
pub fn main() -> i32 {
    let mut rgates = Vec::new();

    let args = env::args().collect::<Vec<_>>();
    let clients = args[1]
        .parse::<u64>()
        .expect("Unable to parse number of clients");
    let prios = args[2]
        .parse::<u64>()
        .expect("Unable to parse number of priorities");
    let time = args[3]
        .parse::<u64>()
        .expect("Unable to parse time argument");

    let sem = Semaphore::attach("ready").unwrap();
    for _ in 0..clients {
        sem.up().unwrap();
    }

    for p in 1..=prios {
        let name = format!("chan{}", p);
        let mut rgate =
            RecvGate::new_named(&name).expect(&format!("Unable to create receive gate {}", name));
        rgate.activate().expect("Unable to activate receive gate");
        rgates.push(rgate);
    }

    loop {
        let mut msg = fetch_msg(&rgates);

        let end = TimeInstant::now() + TimeDuration::from_micros(time);
        while TimeInstant::now() < end {}

        msg.reply_aligned(BUF.borrow().as_ptr(), 8).unwrap();
    }
}
