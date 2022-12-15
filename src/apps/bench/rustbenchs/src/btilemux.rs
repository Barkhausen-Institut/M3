/*
 * Copyright (C) 2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019-2022 Nils Asmussen, Barkhausen Institut
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

use core::fmt;
use m3::cfg;
use m3::com::MemGate;
use m3::goff;
use m3::kif::Perm;
use m3::session::MapFlags;
use m3::test::WvTester;
use m3::tiles::Activity;
use m3::time::{CycleDuration, CycleInstant, Duration, Profiler, Results, Runner};
use m3::tmif;
use m3::{println, wv_perf, wv_run_test};

pub fn run(t: &mut dyn WvTester) {
    wv_run_test!(t, tmcalls);
    wv_run_test!(t, translates);
}

fn tmcalls(_t: &mut dyn WvTester) {
    let prof = Profiler::default().repeats(100).warmup(30);
    wv_perf!(
        "noop tmcall",
        prof.run::<CycleInstant, _>(|| tmif::noop().unwrap())
    );
}

fn translates(_t: &mut dyn WvTester) {
    if Activity::own().pager().is_none() {
        println!("Tile has no virtual memory support; skipping translate benchmark");
        return;
    }

    const VIRT: goff = 0x3000_0000;
    const PAGES: usize = 16;

    struct Tester {
        virt: usize,
        mgate: MemGate,
    }

    impl Runner for Tester {
        fn pre(&mut self) {
            // create new mapping
            self.virt = Activity::own()
                .pager()
                .unwrap()
                .map_anon(VIRT, PAGES * cfg::PAGE_SIZE, Perm::RW, MapFlags::PRIVATE)
                .unwrap() as usize;

            // touch all pages to map them
            let buf: *mut u8 = self.virt as *mut u8;
            for p in 0..PAGES {
                let _byte = unsafe { buf.add(p * cfg::PAGE_SIZE).read_volatile() };
            }
        }

        fn run(&mut self) {
            // now access every page via TCU transfer, which triggers a TLB miss in the TCU
            let buf: *mut u8 = self.virt as *mut u8;
            for p in 0..PAGES {
                let page_buf = unsafe { buf.add(p * cfg::PAGE_SIZE) };
                self.mgate
                    .read_bytes(page_buf, 1, (p * cfg::PAGE_SIZE) as goff)
                    .unwrap();
            }
        }

        fn post(&mut self) {
            // remove mapping
            Activity::own()
                .pager()
                .unwrap()
                .unmap(self.virt as goff)
                .unwrap();
        }
    }

    struct MyResults(Results<CycleDuration>);

    impl fmt::Display for MyResults {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "{} cycles (+/- {} with {} runs)",
                self.0.avg().as_raw() / PAGES as u64,
                self.0.stddev().as_raw() / PAGES as u64,
                self.0.runs()
            )
        }
    }

    let prof = Profiler::default().repeats(10).warmup(2);
    let results = MyResults(prof.runner::<CycleInstant, _>(&mut Tester {
        virt: 0,
        mgate: MemGate::new(PAGES * cfg::PAGE_SIZE, Perm::RW).unwrap(),
    }));

    wv_perf!("TCU read (1 byte) with translate", results);
}
