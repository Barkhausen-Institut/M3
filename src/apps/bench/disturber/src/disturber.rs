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

use core::fmt;
use core::ptr;

use m3::col::Vec;
use m3::com::{MemGate, Semaphore};
use m3::env;
use m3::kif::Perm;
use m3::time::{CycleDuration, CycleInstant, Profiler, Results, Runner};
use m3::{vec, wv_perf};

fn run_workload<F: FnMut()>(
    prof: &mut Profiler,
    sem: Option<&mut Semaphore>,
    wl: F,
) -> Results<CycleDuration> {
    struct MyRunner<'a, F: FnMut()> {
        sem: Option<&'a mut Semaphore>,
        wl: F,
    }

    impl<'a, F: FnMut()> Runner for MyRunner<'a, F> {
        fn pre(&mut self) {
            if let Some(sem) = self.sem.take() {
                sem.up().unwrap();
            }
        }

        fn run(&mut self) {
            (self.wl)();
        }
    }

    prof.runner::<CycleInstant, _>(&mut MyRunner::<F> { sem, wl })
}

fn compute(prof: &mut Profiler, sem: Option<&mut Semaphore>) -> Results<CycleDuration> {
    run_workload(prof, sem, || {
        let val = 4;
        let mut sum = 0;
        for _ in 0..10000 {
            unsafe {
                let v = ptr::read_volatile(&val as *const _);
                ptr::write_volatile(&mut sum as *mut _, sum + v);
            }
        }
        assert_eq!(sum, val * 10000);
    })
}

fn transfers(prof: &mut Profiler, sem: Option<&mut Semaphore>) -> Results<CycleDuration> {
    let mut buf = vec![0u8; 8 * 1024];
    let mgate = MemGate::new(8 * 1024, Perm::RW).expect("Unable to allocate memory");

    run_workload(prof, sem, || {
        for _ in 0..100 {
            mgate.write(&buf, 0).unwrap();
            mgate.read(&mut buf, 0).unwrap();
        }
    })
}

fn memory(prof: &mut Profiler, sem: Option<&mut Semaphore>) -> Results<CycleDuration> {
    let mut buf = vec![0u8; 1024 * 1024];
    let (head, tail) = buf.split_at_mut(512 * 1024);

    let mut count = 0;
    run_workload(prof, sem, || {
        if count % 2 == 0 {
            head.copy_from_slice(tail);
        }
        else {
            tail.copy_from_slice(head);
        }
        count += 1;
    })
}

struct MyResults(Results<CycleDuration>);

impl fmt::Display for MyResults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} (+/- {:?} with {} runs)",
            self.0.times().iter().max().unwrap(),
            self.0.stddev(),
            self.0.runs()
        )
    }
}

#[no_mangle]
pub fn main() -> i32 {
    let args = env::args().collect::<Vec<_>>();
    let mode = args[1];
    let iters = args[2]
        .parse::<u64>()
        .expect("Unable to parse iters argument");
    let semdowns = args[3]
        .parse::<u64>()
        .expect("Unable to parse semdowns argument");

    let mut sem = Semaphore::attach("init").unwrap();
    let sem = if semdowns > 0 {
        for _ in 0..semdowns {
            sem.down().unwrap();
        }
        None
    }
    else {
        Some(&mut sem)
    };

    let mut prof = Profiler::default().repeats(iters).warmup(1);
    let res = match mode {
        "compute" => compute(&mut prof, sem),
        "transfers" => transfers(&mut prof, sem),
        "memory" => memory(&mut prof, sem),
        _ => panic!("Unsupported mode {}", mode),
    };
    wv_perf!(mode, MyResults(res));

    0
}
