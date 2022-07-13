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

use m3::cap::Selector;
use m3::com::{recv_msg, RecvGate, SGateArgs, SendGate};
use m3::rc::Rc;
use m3::tcu;
use m3::test::{DefaultWvTester, WvTester};
use m3::tiles::{Activity, ActivityArgs, ChildActivity, RunningActivity, Tile};
use m3::time::{CycleInstant, Duration, Profiler, TimeDuration};
use m3::{
    format, println, reply_vmsg, send_vmsg, wv_assert_eq, wv_assert_ok, wv_perf, wv_run_test,
};

const MSG_ORD: u32 = 8;

const WARMUP: u64 = 50;
const RUNS: u64 = 1000;

pub fn run(t: &mut dyn WvTester) {
    wv_run_test!(t, pingpong_remote);
    wv_run_test!(t, pingpong_local);
    wv_run_test!(t, pingpong_with_multiple);
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

    let tile = Activity::own().tile().clone();
    // give the child half of our time quota (minimize timer interrupts)
    let own_quota = wv_assert_ok!(tile.quota()).time().total();
    let tile = wv_assert_ok!(tile.derive(None, None, Some(own_quota / 2), None));
    pingpong_with_tile(t, "local", tile);
}

fn pingpong_with_tile(t: &mut dyn WvTester, name: &str, tile: Rc<Tile>) {
    let mut act = wv_assert_ok!(ChildActivity::new_with(tile, ActivityArgs::new("sender")));

    let rgate = wv_assert_ok!(RecvGate::new(MSG_ORD, MSG_ORD));
    let sgate = wv_assert_ok!(SendGate::new_with(SGateArgs::new(&rgate).credits(1)));

    wv_assert_ok!(act.delegate_obj(rgate.sel()));

    let mut dst = act.data_sink();
    dst.push(rgate.sel());

    let act = wv_assert_ok!(act.run(|| {
        let mut t = DefaultWvTester::default();
        let rgate_sel: Selector = Activity::own().data_source().pop().unwrap();
        let mut rgate = RecvGate::new_bind(rgate_sel, MSG_ORD, MSG_ORD);
        wv_assert_ok!(rgate.activate());
        for _ in 0..RUNS + WARMUP {
            let mut msg = wv_assert_ok!(recv_msg(&rgate));
            wv_assert_eq!(t, msg.pop::<u64>(), Ok(0));
            wv_assert_ok!(reply_vmsg!(msg, 0u64));
        }
        0
    }));

    let mut prof = Profiler::default().repeats(RUNS).warmup(WARMUP);

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

fn pingpong_with_multiple(t: &mut dyn WvTester) {
    if !Activity::own().tile_desc().has_virtmem() {
        println!("No virtual memory; skipping remote multi IPC test");
        return;
    }

    let tile = wv_assert_ok!(Tile::get("clone"));
    // use long time slices for childs (minimize timer interrupts)
    wv_assert_ok!(tile.set_quota(
        tcu::MEM_BW_UNLIMITED,
        TimeDuration::from_secs(1).as_raw(),
        tile.quota().unwrap().page_tables().left(),
    ));

    // split time quota between childs
    let cur_quota = wv_assert_ok!(tile.quota()).time().total();
    let tile1 = wv_assert_ok!(tile.derive(None, None, Some(cur_quota / 2), None));
    let tile2 = wv_assert_ok!(tile.derive(None, None, Some(cur_quota / 2), None));

    let mut act1 = wv_assert_ok!(ChildActivity::new_with(tile1, ActivityArgs::new("recv1")));
    let mut act2 = wv_assert_ok!(ChildActivity::new_with(tile2, ActivityArgs::new("recv2")));

    let rgate1 = wv_assert_ok!(RecvGate::new(MSG_ORD, MSG_ORD));
    let rgate2 = wv_assert_ok!(RecvGate::new(MSG_ORD, MSG_ORD));
    let sgate1 = wv_assert_ok!(SendGate::new_with(SGateArgs::new(&rgate1).credits(1)));
    let sgate2 = wv_assert_ok!(SendGate::new_with(SGateArgs::new(&rgate2).credits(1)));

    wv_assert_ok!(act1.delegate_obj(rgate1.sel()));
    wv_assert_ok!(act2.delegate_obj(rgate2.sel()));

    act1.data_sink().push(rgate1.sel());
    act2.data_sink().push(rgate2.sel());

    let func = || {
        let mut t = DefaultWvTester::default();
        let rgate_sel: Selector = Activity::own().data_source().pop().unwrap();
        let mut rgate = RecvGate::new_bind(rgate_sel, MSG_ORD, MSG_ORD);
        wv_assert_ok!(rgate.activate());
        for _ in 0..(RUNS + WARMUP) / 2 {
            let mut msg = wv_assert_ok!(recv_msg(&rgate));
            wv_assert_eq!(t, msg.pop::<u64>(), Ok(0));
            wv_assert_ok!(reply_vmsg!(msg, 0u64));
        }
        0
    };

    let act1 = wv_assert_ok!(act1.run(func));
    let act2 = wv_assert_ok!(act2.run(func));

    let mut prof = Profiler::default().repeats(RUNS).warmup(WARMUP);

    let mut count = 0;
    let reply_gate = RecvGate::def();
    wv_perf!(
        "remote multi pingpong with (1 * u64) msgs",
        prof.run::<CycleInstant, _>(|| {
            // alternate between bothr receivers to ensure that we always need a context switch on
            // the other tile
            if count % 2 == 0 {
                wv_assert_ok!(send_vmsg!(&sgate1, reply_gate, 0u64));
            }
            else {
                wv_assert_ok!(send_vmsg!(&sgate2, reply_gate, 0u64));
            }

            let mut reply = wv_assert_ok!(recv_msg(reply_gate));
            wv_assert_eq!(t, reply.pop::<u64>(), Ok(0));

            count += 1;
        })
    );

    wv_assert_eq!(t, act1.wait(), Ok(0));
    wv_assert_eq!(t, act2.wait(), Ok(0));
}
