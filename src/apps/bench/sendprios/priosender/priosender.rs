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
use m3::col::{String, Vec};
use m3::com::{recv_msg, RGateArgs, RecvGate, Semaphore, SendGate};
use m3::env;
use m3::mem::AlignedBuf;
use m3::time::{Duration, Profiler, TimeInstant};
use m3::{format, print, wv_assert_ok, wv_perf};

static BUF: StaticRefCell<AlignedBuf<2048>> = StaticRefCell::new(AlignedBuf::new_zeroed());

#[no_mangle]
pub fn main() -> i32 {
    let args = env::args().collect::<Vec<_>>();
    let prio = args[1].parse::<u64>().expect("Unable to parse priority");
    let runs = args[2]
        .parse::<u64>()
        .expect("Unable to parse number of runs argument");
    let warmup = args[3]
        .parse::<u64>()
        .expect("Unable to parse number of warmups argument");
    let print = args[4]
        .parse::<u32>()
        .expect("Unable to parse print argument");

    let sgate = wv_assert_ok!(SendGate::new_named(&format!("chan{}", prio)));
    wv_assert_ok!(sgate.activate());

    let reply_gate = RecvGate::new_with(RGateArgs::default().order(6).msg_order(6)).unwrap();
    wv_assert_ok!(reply_gate.activate());

    wv_assert_ok!(Semaphore::attach("ready").unwrap().down());

    let prof = Profiler::default().repeats(runs).warmup(warmup);

    let res = prof.run::<TimeInstant, _>(|| {
        wv_assert_ok!(sgate.send_aligned(BUF.borrow().as_ptr(), 8, &reply_gate));
        wv_assert_ok!(recv_msg(&reply_gate));
    });

    if print > 0 {
        wv_perf!(&format!("prio{}", prio), &res);
        if print > 1 {
            let mut all = String::new();
            for r in res.times() {
                all += &format!("p{}: {}\n", prio, r.as_raw());
            }
            print!("{}", all);
        }
    }

    0
}
