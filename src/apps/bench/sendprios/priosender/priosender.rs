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

use core::fmt;

use m3::cell::StaticRefCell;
use m3::col::{String, Vec};
use m3::com::{recv_msg, RGateArgs, RecvGate, Semaphore, SendGate};
use m3::env;
use m3::mem::AlignedBuf;
use m3::tiles::Activity;
use m3::time::{Duration, Profiler, Results, Runner, TimeDuration, TimeInstant};
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
    let post_wait = args[4]
        .parse::<u64>()
        .expect("Unable to post wait argument");
    let print = args[5]
        .parse::<u32>()
        .expect("Unable to parse print argument");

    let sgate = wv_assert_ok!(SendGate::new_named(&format!("chan{}", prio)));
    wv_assert_ok!(sgate.activate());

    let mut reply_gate = RecvGate::new_with(RGateArgs::default().order(6).msg_order(6)).unwrap();
    wv_assert_ok!(reply_gate.activate());

    wv_assert_ok!(Semaphore::attach("ready").unwrap().down());

    let mut prof = Profiler::default().repeats(runs).warmup(warmup);

    struct Sender<'s, 'r>(&'s SendGate, &'r RecvGate, u64);
    impl<'s, 'r> Runner for Sender<'s, 'r> {
        fn run(&mut self) {
            wv_assert_ok!(self.0.send_aligned(BUF.borrow().as_ptr(), 1, self.1));
            wv_assert_ok!(recv_msg(self.1));
        }

        fn post(&mut self) {
            if self.2 > 0 {
                Activity::own()
                    .sleep_for(TimeDuration::from_millis(self.2))
                    .unwrap();
            }
        }
    }

    let res = prof.runner::<TimeInstant, _>(&mut Sender(&sgate, &reply_gate, post_wait));

    struct MyResults<'r>(&'r Results<TimeDuration>);
    impl fmt::Display for MyResults<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "{:?} (+/- {:?} with {} runs)",
                self.0.times().iter().max().unwrap(),
                self.0.stddev(),
                self.0.runs()
            )
        }
    }

    if print > 0 {
        wv_perf!(&format!("prio{}", prio), MyResults(&res));
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
