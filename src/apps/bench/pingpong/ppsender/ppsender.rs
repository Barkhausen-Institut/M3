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
use m3::com::{recv_msg, RGateArgs, RecvGate, Semaphore, SendGate};
use m3::env;
use m3::mem::AlignedBuf;
use m3::tiles::Activity;
use m3::time::{CycleInstant, Duration, Profiler, TimeDuration};
use m3::util::math::next_log2;
use m3::{println, wv_assert_ok, wv_perf};

static BUF: StaticRefCell<AlignedBuf<2048>> = StaticRefCell::new(AlignedBuf::new_zeroed());

#[no_mangle]
pub fn main() -> i32 {
    let args = env::args().collect::<Vec<_>>();
    let runs = args[1]
        .parse::<u64>()
        .expect("Unable to parse number of runs argument");
    let warmup = args[2]
        .parse::<u64>()
        .expect("Unable to parse number of warmups argument");
    let msgsize = args[3]
        .parse::<usize>()
        .expect("Unable to parse message size argument");
    let print = args[4]
        .parse::<u32>()
        .expect("Unable to parse print argument");

    let sgate = wv_assert_ok!(SendGate::new_named("chan"));
    wv_assert_ok!(sgate.activate());

    let msg_order = next_log2(msgsize.max(16 + msgsize));
    let mut reply_gate =
        RecvGate::new_with(RGateArgs::default().order(msg_order).msg_order(msg_order)).unwrap();
    wv_assert_ok!(reply_gate.activate());

    let mut prof = Profiler::default().repeats(runs).warmup(warmup);

    wv_assert_ok!(Semaphore::attach("ready").unwrap().down());

    let res = prof.run::<CycleInstant, _>(|| {
        wv_assert_ok!(sgate.send_aligned(BUF.borrow().as_ptr(), msgsize, &reply_gate));

        wv_assert_ok!(recv_msg(&reply_gate));
    });

    if print > 0 {
        wv_perf!("pingpong", &res);
        if print > 1 {
            for r in res.times() {
                println!("{}", r.as_raw());
                Activity::own()
                    .sleep_for(TimeDuration::from_micros(1))
                    .unwrap();
            }
        }
    }

    0
}
