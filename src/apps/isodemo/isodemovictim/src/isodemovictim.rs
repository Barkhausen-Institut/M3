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

use m3::cfg;
use m3::client::MapFlags;
use m3::env;
use m3::errors::Error;
use m3::kif::Perm;
use m3::mem::VirtAddr;
use m3::println;
use m3::tiles::{Activity, OwnActivity};
use m3::time::TimeDuration;

#[no_mangle]
pub fn main() -> Result<(), Error> {
    let word = if let Some(arg) = env::args().nth(1) {
        arg
    }
    else {
        "hello"
    };

    let virt = VirtAddr::from(0x3000_0000);
    Activity::own()
        .pager()
        .unwrap()
        .map_anon(virt, cfg::PAGE_SIZE, Perm::RW, MapFlags::PRIVATE)
        .expect("Unable to map anon memory");

    unsafe {
        core::ptr::copy_nonoverlapping(word.as_ptr(), virt.as_mut_ptr(), word.len());
    }
    let word_copy: &[u8] = unsafe { core::slice::from_raw_parts(virt.as_ptr(), word.len()) };

    loop {
        println!("!! victim: {:?}", core::str::from_utf8(word_copy).unwrap());
        OwnActivity::sleep_for(TimeDuration::from_secs(1)).unwrap();
    }
}
