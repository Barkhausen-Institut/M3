/*
 * Copyright (C) 2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019-2021 Nils Asmussen, Barkhausen Institut
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

use m3::cell::StaticRefCell;
use m3::com::MemGate;
use m3::kif;
use m3::mem::AlignedBuf;
use m3::test::WvTester;
use m3::time::{CycleInstant, Profiler};
use m3::{wv_perf, wv_run_test};

const SIZE: usize = 2 * 1024 * 1024;

static BUF: StaticRefCell<AlignedBuf<{ 8192 + 64 }>> = StaticRefCell::new(AlignedBuf::new_zeroed());

pub fn run(t: &mut dyn WvTester) {
    wv_run_test!(t, read);
    wv_run_test!(t, read_unaligned);
    wv_run_test!(t, write);
    wv_run_test!(t, write_unaligned);
}

fn read(_t: &mut dyn WvTester) {
    let buf = &mut BUF.borrow_mut()[..8192];
    let mgate = MemGate::new(8192, kif::Perm::R).expect("Unable to create mgate");

    let prof = Profiler::default().repeats(2).warmup(1);

    wv_perf!(
        "read 2 MiB with 8K buf",
        prof.run::<CycleInstant, _>(|| {
            let mut total = 0;
            while total < SIZE {
                mgate.read(buf, 0).expect("Reading failed");
                total += buf.len();
            }
        })
    );
}

fn read_unaligned(_t: &mut dyn WvTester) {
    let buf = &mut BUF.borrow_mut()[64..];
    let mgate = MemGate::new(8192, kif::Perm::R).expect("Unable to create mgate");

    let prof = Profiler::default().repeats(2).warmup(1);

    wv_perf!(
        "read unaligned 2 MiB with 8K buf",
        prof.run::<CycleInstant, _>(|| {
            let mut total = 0;
            while total < SIZE {
                mgate.read(buf, 0).expect("Reading failed");
                total += buf.len();
            }
        })
    );
}

fn write(_t: &mut dyn WvTester) {
    let buf = &BUF.borrow()[..8192];
    let mgate = MemGate::new(8192, kif::Perm::W).expect("Unable to create mgate");

    let prof = Profiler::default().repeats(2).warmup(1);

    wv_perf!(
        "write 2 MiB with 8K buf",
        prof.run::<CycleInstant, _>(|| {
            let mut total = 0;
            while total < SIZE {
                mgate.write(buf, 0).expect("Writing failed");
                total += buf.len();
            }
        })
    );
}

fn write_unaligned(_t: &mut dyn WvTester) {
    let buf = &BUF.borrow()[64..];
    let mgate = MemGate::new(8192, kif::Perm::W).expect("Unable to create mgate");

    let prof = Profiler::default().repeats(2).warmup(1);

    wv_perf!(
        "write unaligned 2 MiB with 8K buf",
        prof.run::<CycleInstant, _>(|| {
            let mut total = 0;
            while total < SIZE {
                mgate.write(buf, 0).expect("Writing failed");
                total += buf.len();
            }
        })
    );
}
