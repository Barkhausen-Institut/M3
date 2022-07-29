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

use core::ptr;

use m3::col::Vec;
use m3::com::MemGate;
use m3::env;
use m3::kif::Perm;
use m3::time::{CycleDuration, CycleInstant, Profiler, Results};
use m3::{vec, wv_perf};

fn compute(prof: &mut Profiler) -> Results<CycleDuration> {
    prof.run::<CycleInstant, _>(|| unsafe {
        let val = 4;
        let mut sum = 0;
        for _ in 0..100000 {
            let v = ptr::read_volatile(&val as *const _);
            ptr::write_volatile(&mut sum as *mut _, sum + v);
        }
        assert_eq!(sum, val * 100000);
    })
}

fn transfers(prof: &mut Profiler) -> Results<CycleDuration> {
    let mut buf = vec![0u8; 8 * 1024];
    let mgate = MemGate::new(8 * 1024, Perm::RW).expect("Unable to allocate memory");

    prof.run::<CycleInstant, _>(|| {
        for _ in 0..100 {
            mgate.write(&buf, 0).unwrap();
            mgate.read(&mut buf, 0).unwrap();
        }
    })
}

fn memory(prof: &mut Profiler) -> Results<CycleDuration> {
    let mut buf = vec![0u8; 1024 * 1024];
    let (head, tail) = buf.split_at_mut(512 * 1024);

    let mut count = 0;
    prof.run::<CycleInstant, _>(|| {
        if count % 2 == 0 {
            head.copy_from_slice(tail);
        }
        else {
            tail.copy_from_slice(head);
        }
        count += 1;
    })
}

#[no_mangle]
pub fn main() -> i32 {
    let args = env::args().collect::<Vec<_>>();
    let mode = args[1];
    let iters = args[2]
        .parse::<u64>()
        .expect("Unable to parse iters argument");

    let mut prof = Profiler::default().repeats(iters).warmup(10);
    let res = match mode {
        "compute" => compute(&mut prof),
        "transfers" => transfers(&mut prof),
        "memory" => memory(&mut prof),
        _ => panic!("Unsupported mode {}", mode),
    };
    wv_perf!(mode, &res);

    0
}
