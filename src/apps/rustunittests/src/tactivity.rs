/*
 * Copyright (C) 2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019-2022 Nils Asmussen, Barkhausen Institut
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
use m3::env;
use m3::math;
use m3::test::{DefaultWvTester, WvTester};
use m3::tiles::{Activity, ActivityArgs, ChildActivity, RunningActivity, Tile};
use m3::time::TimeDuration;

use m3::{send_vmsg, wv_assert_eq, wv_assert_ok, wv_run_test};

use m3::com::channel;
use m3::errors::Error;

pub fn run(t: &mut dyn WvTester) {
    wv_run_test!(t, run_stop);
    wv_run_test!(t, run_arguments);
    wv_run_test!(t, run_send_receive);
    #[cfg(not(target_vendor = "host"))]
    wv_run_test!(t, exec_fail);
    wv_run_test!(t, exec_hello);
    wv_run_test!(t, exec_rust_hello);
}

fn run_stop(_t: &mut dyn WvTester) {
    use m3::com::RGateArgs;
    use m3::vfs;

    let mut rg = wv_assert_ok!(RecvGate::new_with(
        RGateArgs::default().order(6).msg_order(6)
    ));
    wv_assert_ok!(rg.activate());

    let tile = wv_assert_ok!(Tile::get("clone|own"));

    let mut wait_time = TimeDuration::from_nanos(10000);
    for _ in 1..100 {
        let mut act = wv_assert_ok!(ChildActivity::new_with(
            tile.clone(),
            ActivityArgs::new("test")
        ));

        // pass sendgate to child
        let sg = wv_assert_ok!(SendGate::new_with(SGateArgs::new(&rg).credits(1)));
        wv_assert_ok!(act.delegate_obj(sg.sel()));

        // pass root fs to child
        act.add_mount("/", "/");

        let mut dst = act.data_sink();
        dst.push(sg.sel());

        let act = wv_assert_ok!(act.run(|| {
            let mut src = Activity::own().data_source();
            let sg_sel: Selector = src.pop().unwrap();

            // notify parent that we're running
            let sg = SendGate::new_bind(sg_sel);
            wv_assert_ok!(send_vmsg!(&sg, RecvGate::def(), 1));
            let mut _n = 0;
            loop {
                _n += 1;
                // just to execute more interesting instructions than arithmetic or jumps
                vfs::VFS::stat("/").ok();
            }
        }));

        // wait for child
        wv_assert_ok!(recv_msg(&rg));

        // wait a bit and stop activity
        wv_assert_ok!(Activity::own().sleep_for(wait_time));
        wv_assert_ok!(act.stop());

        // increase by one ns to attempt interrupts at many points in the instruction stream
        wait_time += TimeDuration::from_nanos(1);
    }
}

fn run_arguments(t: &mut dyn WvTester) {
    let tile = wv_assert_ok!(Tile::get("clone|own"));
    let act = wv_assert_ok!(ChildActivity::new_with(tile, ActivityArgs::new("test")));

    let act = wv_assert_ok!(act.run(|| {
        let mut t = DefaultWvTester::default();
        wv_assert_eq!(t, env::args().count(), 1);
        assert!(env::args().next().is_some());
        assert!(env::args().next().unwrap().ends_with("rustunittests"));
        0
    }));

    wv_assert_eq!(t, act.wait(), Ok(0));
}

fn run_send_receive(t: &mut dyn WvTester) {
    let tile = wv_assert_ok!(Tile::get("clone|own"));
    let mut act = wv_assert_ok!(ChildActivity::new_with(tile, ActivityArgs::new("test")));

    let rgate = wv_assert_ok!(RecvGate::new(math::next_log2(256), math::next_log2(256)));
    let sgate = wv_assert_ok!(SendGate::new_with(SGateArgs::new(&rgate).credits(1)));

    wv_assert_ok!(act.delegate_obj(rgate.sel()));

    let mut dst = act.data_sink();
    dst.push(rgate.sel());

    let act = wv_assert_ok!(act.run(|| {
        let mut t = DefaultWvTester::default();
        let mut src = Activity::own().data_source();
        let rg_sel: Selector = src.pop().unwrap();

        let mut rgate = RecvGate::new_bind(rg_sel, math::next_log2(256), math::next_log2(256));
        wv_assert_ok!(rgate.activate());
        let mut res = wv_assert_ok!(recv_msg(&rgate));
        let i1 = wv_assert_ok!(res.pop::<u32>());
        let i2 = wv_assert_ok!(res.pop::<u32>());
        wv_assert_eq!(t, (i1, i2), (42, 23));
        (i1 + i2) as i32
    }));

    wv_assert_ok!(send_vmsg!(&sgate, RecvGate::def(), 42, 23));

    wv_assert_eq!(t, act.wait(), Ok(42 + 23));
}

fn run_send_receive_chan(t: &mut dyn WvTester) {
    let tile = wv_assert_ok!(Tile::get("clone|own"));
    let mut act = wv_assert_ok!(ChildActivity::new_with(tile, ActivityArgs::new("test")));

    let (tx, rx) = wv_assert_ok!(channel::channel_def());
    let (res_tx, res_rx) = wv_assert_ok!(channel::channel_def());

    // TODO hide this in channel creation
    wv_assert_ok!(act.delegate_obj(rx.cap_sel()));
    wv_assert_ok!(act.delegate_obj(res_tx.cap_sel()));

    let mut act_sel = act.data_sink();
    act_sel.push(rx.cap_sel());
    act_sel.push(res_tx.cap_sel());

    let future = wv_assert_ok!(act.run(|| {
        let f = || -> Result<(), Error> {
            let rx = channel::Receiver::activate_def()?;
            let res_tx = channel::Sender::activate()?;

            let i1 = rx.recv::<u32>()?;
            let res = (i1 + 5) as i32;

            res_tx.send(res)?;
            Ok(())
        };
        f().map(|_| 0).unwrap() // currently necessary because of the API
    }));

    //wv_assert_ok!(tx.activate());
    //wv_assert_ok!(res_rx.activate());

    wv_assert_ok!(tx.send::<u32>(42));
    wv_assert_ok!(future.wait());

    let res :i32 = res_rx.recv().unwrap();
    wv_assert_eq!(t, res, 42 + 5);
}

#[cfg(not(target_vendor = "host"))]
fn exec_fail(_t: &mut dyn WvTester) {
    use m3::errors::Code;

    let tile = wv_assert_ok!(Tile::get("clone|own"));
    // file too small
    {
        let act = wv_assert_ok!(ChildActivity::new_with(
            tile.clone(),
            ActivityArgs::new("test")
        ));
        let act = act.exec(&["/testfile.txt"]);
        assert!(act.is_err() && act.err().unwrap().code() == Code::EndOfFile);
    }

    // not an ELF file
    {
        let act = wv_assert_ok!(ChildActivity::new_with(tile, ActivityArgs::new("test")));
        let act = act.exec(&["/pat.bin"]);
        assert!(act.is_err() && act.err().unwrap().code() == Code::InvalidElf);
    }
}

fn exec_hello(t: &mut dyn WvTester) {
    let tile = wv_assert_ok!(Tile::get("clone|own"));
    let act = wv_assert_ok!(ChildActivity::new_with(tile, ActivityArgs::new("test")));

    let act = wv_assert_ok!(act.exec(&["/bin/hello"]));
    wv_assert_eq!(t, act.wait(), Ok(0));
}

fn exec_rust_hello(t: &mut dyn WvTester) {
    let tile = wv_assert_ok!(Tile::get("clone|own"));
    let act = wv_assert_ok!(ChildActivity::new_with(tile, ActivityArgs::new("test")));

    let act = wv_assert_ok!(act.exec(&["/bin/rusthello"]));
    wv_assert_eq!(t, act.wait(), Ok(0));
}
