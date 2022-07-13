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

use m3::cell::StaticRefCell;
use m3::com::{MGateArgs, MemGate};
use m3::goff;
use m3::kif::Perm;
use m3::mem::AlignedBuf;
use m3::println;
use m3::time::{TimeDuration, TimeInstant};

const CHUNK_SIZE: usize = 4096;

static BUF: StaticRefCell<AlignedBuf<CHUNK_SIZE>> = StaticRefCell::new(AlignedBuf::new_zeroed());

#[no_mangle]
pub fn main() -> i32 {
    let mem = MemGate::new_with(MGateArgs::new(CHUNK_SIZE * 2, Perm::RW))
        .expect("Unable to allocate memory");

    let mut total = 0;

    let start = TimeInstant::now();
    let end = start + TimeDuration::from_millis(10);
    while TimeInstant::now() < end {
        mem.read(&mut BUF.borrow_mut()[..], 0)
            .expect("Reading failed");
        mem.write(&BUF.borrow()[..], CHUNK_SIZE as goff)
            .expect("Writing failed");

        total += CHUNK_SIZE * 2;
    }

    let duration = TimeInstant::now().duration_since(start);
    println!(
        "Transferred {} bytes in {}ms: {} b/s",
        total,
        duration.as_millis(),
        1000. * ((total as f64) / (duration.as_millis() as f64))
    );

    0
}
