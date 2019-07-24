/*
 * Copyright (C) 2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
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

use m3::col::String;
use m3::com::{recv_msg, recv_reply, RecvGate, SendGate, SGateArgs};
use m3::errors::Code;
use m3::test;
use m3::util;

pub fn run(t: &mut dyn test::WvTester) {
    wv_run_test!(t, create);
    wv_run_test!(t, send_recv);
    wv_run_test!(t, send_reply);
}

fn create() {
    let rgate = wv_assert_ok!(RecvGate::new(util::next_log2(512), util::next_log2(256)));
    wv_assert_err!(SendGate::new_with(SGateArgs::new(&rgate).sel(1)), Code::InvArgs);
}

fn send_recv() {
    let mut rgate = wv_assert_ok!(RecvGate::new(util::next_log2(512), util::next_log2(256)));
    let sgate = wv_assert_ok!(SendGate::new_with(
        SGateArgs::new(&rgate).credits(512).label(0x1234)
    ));
    assert!(sgate.ep().is_none());
    wv_assert_ok!(rgate.activate());

    let data = [0u8; 16];
    wv_assert_ok!(sgate.send(&data, RecvGate::def()));
    assert!(sgate.ep().is_some());
    wv_assert_ok!(sgate.send(&data, RecvGate::def()));
    wv_assert_err!(sgate.send(&data, RecvGate::def()), Code::MissCredits);

    {
        let is = wv_assert_ok!(rgate.wait(Some(&sgate)));
        wv_assert_eq!(is.label(), 0x1234);
    }

    {
        let is = wv_assert_ok!(rgate.wait(Some(&sgate)));
        wv_assert_eq!(is.label(), 0x1234);
    }
}

fn send_reply() {
    let reply_gate = RecvGate::def();
    let mut rgate = wv_assert_ok!(RecvGate::new(util::next_log2(64), util::next_log2(64)));
    let sgate = wv_assert_ok!(SendGate::new_with(
        SGateArgs::new(&rgate).credits(64).label(0x1234)
    ));
    assert!(sgate.ep().is_none());
    wv_assert_ok!(rgate.activate());

    wv_assert_ok!(send_vmsg!(&sgate, &reply_gate, 0x123, 12, "test"));

    // sgate -> rgate
    {
        let mut msg = wv_assert_ok!(recv_msg(&rgate));
        let (i1, i2, s): (i32, i32, String) = (msg.pop(), msg.pop(), msg.pop());
        wv_assert_eq!(i1, 0x123);
        wv_assert_eq!(i2, 12);
        wv_assert_eq!(s, "test");

        wv_assert_ok!(reply_vmsg!(msg, 44, 3));
    }

    // rgate -> reply_gate
    {
        let mut reply = wv_assert_ok!(recv_reply(&reply_gate, Some(&sgate)));
        let (i1, i2): (i32, i32) = (reply.pop(), reply.pop());
        wv_assert_eq!(i1, 44);
        wv_assert_eq!(i2, 3);
    }
}
