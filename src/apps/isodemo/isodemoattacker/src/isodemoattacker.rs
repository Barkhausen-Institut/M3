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

use core::mem::size_of;
use core::ptr::write_volatile;

use m3::cap::Selector;
use m3::client::MapFlags;
use m3::com::{recv_msg, RecvGate};
use m3::errors::{Code, Error};
use m3::kif::Perm;
use m3::mem::VirtAddr;
use m3::tiles::Activity;
use m3::vec::Vec;
use m3::{cfg, tmif};
use m3::{env, reply_vmsg};

use common::{ChildReply, ChildReq, Value};

macro_rules! log {
    ($fmt:expr, $($arg:tt)*) => {
        m3::println!(concat!("!! attacker: ", $fmt), $($arg)*)
    };
}

fn perform_attack(virt: VirtAddr, val: Value) {
    tmif::act_info(virt, virt).unwrap();

    unsafe {
        let count = *virt.as_ptr::<u64>().offset(0) as isize;
        let page_table = VirtAddr::from(*virt.as_ptr::<u64>().offset(1) as usize);

        assert!(count <= 4);
        log!("found {} victims, using page_table {}", count, page_table);

        // start with fourth page, because the pager faults in 4 pages at once
        let start_page = 4;

        for i in 0..count {
            let pte = *virt.as_ptr::<u64>().offset(2 + i);
            log!("getting access to victim {} (pte={:#x})", i, pte);

            let pte_addr =
                VirtAddr::from(page_table + (start_page + i) as usize * size_of::<u64>());
            // insert PTE to access victim page
            write_volatile(pte_addr.as_mut_ptr(), pte);

            log!("overwriting with {} in victim {}", val, i);

            // overwrite beginning of victim page
            let page_addr = virt + (start_page + i) as usize * cfg::PAGE_SIZE;
            let vals: [Value; 1] = [val];
            core::ptr::copy_nonoverlapping(vals.as_ptr(), page_addr.as_mut_ptr(), vals.len());
            log!("done with victim {}!", i);
        }
    }
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
        .map_anon(virt, cfg::PAGE_SIZE * 8, Perm::RW, MapFlags::PRIVATE)
        .expect("Unable to map anon memory");

    // fault pages in to create higher level PTEs
    unsafe { *virt.as_mut_ptr() = 42 };

    while let Ok(mut msg) = recv_msg(&req_rgate) {
        let cmd: ChildReq = msg.pop().unwrap();
        let reply = match cmd {
            ChildReq::Attack(val) => {
                perform_attack(virt, val);
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
