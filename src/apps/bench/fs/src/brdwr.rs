/*
 * Copyright (C) 2021 Nils Asmussen, Barkhausen Institut
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
use m3::io::{Read, Write};
use m3::mem::AlignedBuf;
use m3::test::WvTester;
use m3::time::{CycleInstant, Profiler};
use m3::vfs::{OpenFlags, VFS};
use m3::{wv_assert_ok, wv_perf, wv_run_test};

static BUF: StaticRefCell<AlignedBuf<4096>> = StaticRefCell::new(AlignedBuf::new_zeroed());

pub fn run(t: &mut dyn WvTester) {
    wv_run_test!(t, read);
    wv_run_test!(t, write);
}

fn read(_t: &mut dyn WvTester) {
    let buf = &mut BUF.borrow_mut()[..];

    let prof = Profiler::default().repeats(10).warmup(4);

    wv_perf!(
        "read 2 MiB file with 4K buf",
        prof.run::<CycleInstant, _>(|| {
            let mut file = wv_assert_ok!(VFS::open("/data/2048k.txt", OpenFlags::R));
            loop {
                let amount = wv_assert_ok!(file.read(buf));
                if amount == 0 {
                    break;
                }
            }
        })
    );
}

fn write(_t: &mut dyn WvTester) {
    const SIZE: usize = 2 * 1024 * 1024;
    let buf = &BUF.borrow()[..];

    let prof = Profiler::default().repeats(10).warmup(4);

    wv_perf!(
        "write 2 MiB file with 4K buf",
        prof.run::<CycleInstant, _>(|| {
            let mut file = wv_assert_ok!(VFS::open(
                "/newfile",
                OpenFlags::W | OpenFlags::CREATE | OpenFlags::TRUNC
            ));

            let mut total = 0;
            while total < SIZE {
                let amount = wv_assert_ok!(file.write(buf));
                if amount == 0 {
                    break;
                }
                total += amount;
            }
        })
    );
}
