/*
 * Copyright (C) 2020-2022 Nils Asmussen, Barkhausen Institut
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

use m3::com::{recv_msg, RecvGate, SGateArgs, SendGate};
use m3::rc::Rc;
use m3::test::{DefaultWvTester, WvTester};
use m3::tiles::{Activity, ActivityArgs, ChildActivity, RunningActivity, Tile};
use m3::time::{CycleInstant, Profiler};
use m3::{
    format, println, reply_vmsg, send_vmsg, wv_assert_eq, wv_assert_ok, wv_perf, wv_run_test,
};

const MSG_ORD: u32 = 8;

const WARMUP: u64 = 50;
const RUNS: u64 = 1000;

pub fn run(t: &mut dyn WvTester) {
    wv_run_test!(t, pingpong_remote);
    wv_run_test!(t, pingpong_local);
}

fn pingpong_remote(t: &mut dyn WvTester) {
    let tile = wv_assert_ok!(Tile::get("clone"));
    pingpong_with_tile(t, "remote", tile);
}

fn pingpong_local(t: &mut dyn WvTester) {
    if !Activity::own().tile_desc().has_virtmem() {
        println!("No virtual memory; skipping local IPC test");
        return;
    }

    pingpong_with_tile(t, "local", Activity::own().tile().clone());
}

fn pingpong_with_tile(t: &mut dyn WvTester, name: &str, tile: Rc<Tile>) {
    let mut act = wv_assert_ok!(ChildActivity::new_with(tile, ActivityArgs::new("sender")));

    let rgate = wv_assert_ok!(RecvGate::new(MSG_ORD, MSG_ORD));
    let sgate = wv_assert_ok!(SendGate::new_with(SGateArgs::new(&rgate).credits(1)));

    wv_assert_ok!(act.delegate_obj(rgate.sel()));

    let mut dst = act.data_sink();
    dst.push_word(rgate.sel());

    let act = wv_assert_ok!(act.run(|| {
        let mut t = DefaultWvTester::default();
        let rgate_sel = Activity::own().data_source().pop_word().unwrap();
        let mut rgate = RecvGate::new_bind(rgate_sel, MSG_ORD, MSG_ORD);
        wv_assert_ok!(rgate.activate());
        for _ in 0..RUNS + WARMUP {
            let mut msg = wv_assert_ok!(recv_msg(&rgate));
            wv_assert_eq!(t, msg.pop::<u64>(), Ok(0));
            wv_assert_ok!(reply_vmsg!(msg, 0u64));
        }
        0
    }));

    let prof = Profiler::default().repeats(RUNS).warmup(WARMUP);

    let reply_gate = RecvGate::def();
    wv_perf!(
        format!("{} pingpong with (1 * u64) msgs", name),
        prof.run::<CycleInstant, _>(|| {
            wv_assert_ok!(send_vmsg!(&sgate, reply_gate, 0u64));

            let mut reply = wv_assert_ok!(recv_msg(reply_gate));
            wv_assert_eq!(t, reply.pop::<u64>(), Ok(0));
        })
    );

    wv_assert_eq!(t, act.wait(), Ok(0));
}
