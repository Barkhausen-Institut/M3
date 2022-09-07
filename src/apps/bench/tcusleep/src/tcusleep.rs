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

use m3::com::{recv_msg, RecvGate, SendGate};
use m3::cpu;
use m3::env;
use m3::tcu::TCU;
use m3::{reply_vmsg, send_recv};

#[no_mangle]
pub fn main() -> i32 {
    let ty = env::args().nth(1).unwrap();
    let runs = env::args().nth(2).unwrap().parse::<u32>().unwrap();

    if ty == "sender" {
        let sgate = SendGate::new_named("chan").expect("Unable to create send gate");
        for _ in 0..runs {
            send_recv!(&sgate, RecvGate::def(), 0).unwrap();
        }
    }
    else {
        let mut rgate = RecvGate::new_named("chan").expect("Unable to create receive gate");
        rgate.activate().expect("Unable to activate receive gate");

        for _ in 0..runs {
            cpu::gem5_debug(0xDEAD);
            TCU::sleep().unwrap();
            cpu::gem5_debug(0xBEEF);

            let mut reply = recv_msg(&rgate).unwrap();
            reply_vmsg!(reply, 0).unwrap();
        }
    }
    0
}
