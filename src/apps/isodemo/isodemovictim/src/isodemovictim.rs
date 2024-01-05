/*
 * Copyright (C) 2023 Nils Asmussen, Barkhausen Institut
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

#[path = "../../common.rs"]
mod common;

use m3::cap::Selector;
use m3::client::MapFlags;
use m3::com::{recv_msg, RecvGate};
use m3::env;
use m3::errors::{Code, Error};
use m3::kif::Perm;
use m3::mem::VirtAddr;
use m3::tiles::Activity;
use m3::vec::Vec;
use m3::{cfg, reply_vmsg};

use common::{ChildReply, ChildReq};

macro_rules! log {
    ($fmt:expr, $($arg:tt)*) => {
        m3::println!(concat!("!! victim: ", $fmt), $($arg)*)
    };
}

#[no_mangle]
pub fn main() -> Result<(), Error> {
    let args = env::args().collect::<Vec<_>>();

    let req_sel: Selector = args[1].parse().expect("Unable to parse request selector");

    let req_rgate = RecvGate::new_bind(req_sel);

    let virt = VirtAddr::from(0x3000_0000);
    Activity::own()
        .pager()
        .unwrap()
        .map_anon(virt, cfg::PAGE_SIZE, Perm::RW, MapFlags::PRIVATE)
        .expect("Unable to map anon memory");

    let val = [0u8; 1];
    unsafe {
        core::ptr::copy_nonoverlapping(val.as_ptr(), virt.as_mut_ptr(), val.len());
    }
    let val_copy: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(virt.as_mut_ptr(), val.len()) };

    while let Ok(mut msg) = recv_msg(&req_rgate) {
        let cmd: ChildReq = msg.pop().unwrap();
        let reply = match cmd {
            ChildReq::Get => ChildReply::new_with_val(Code::Success, val_copy[0]),
            ChildReq::Set(val) => {
                val_copy[0] = val;
                ChildReply::new(Code::Success)
            },
            _ => {
                log!("unsupported command: {:?}", cmd);
                ChildReply::new(Code::InvArgs)
            },
        };

        reply_vmsg!(msg, reply).unwrap();
    }

    Ok(())
}
