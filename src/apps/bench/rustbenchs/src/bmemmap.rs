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

use m3::col::Vec;
use m3::mem::MemMap;
use m3::test::WvTester;
use m3::time::{CycleInstant, Profiler, Runner};
use m3::{wv_assert_ok, wv_perf, wv_run_test};

pub fn run(t: &mut dyn WvTester) {
    wv_run_test!(t, perf_alloc);
    wv_run_test!(t, perf_free);
}

fn perf_alloc(_t: &mut dyn WvTester) {
    let prof = Profiler::default().repeats(10);

    struct MemMapTester {
        map: MemMap,
    }

    impl Runner for MemMapTester {
        fn pre(&mut self) {
            self.map = MemMap::new(0, 0x0100_0000);
        }

        fn run(&mut self) {
            for _ in 0..100 {
                wv_assert_ok!(self.map.allocate(0x1000, 0x1000));
            }
        }
    }

    let mut tester = MemMapTester {
        map: MemMap::new(0, 0x0010_0000),
    };

    wv_perf!(
        "Allocating 100 areas",
        prof.runner::<CycleInstant, _>(&mut tester)
    );
}

fn perf_free(_t: &mut dyn WvTester) {
    let prof = Profiler::default().repeats(10);

    struct MemMapTester {
        map: MemMap,
        addrs: Vec<u64>,
        forward: bool,
    }

    impl Runner for MemMapTester {
        fn pre(&mut self) {
            self.map = MemMap::new(0, 0x0010_0000);
            self.addrs.clear();
            for _ in 0..100 {
                self.addrs
                    .push(wv_assert_ok!(self.map.allocate(0x1000, 0x1000)));
            }
        }

        fn run(&mut self) {
            for i in 0..100 {
                let idx = if self.forward { i } else { 100 - i - 1 };
                self.map.free(self.addrs[idx], 0x1000);
            }
            assert!(self.map.size() == (0x0010_0000, 1));
        }
    }

    let mut tester = MemMapTester {
        map: MemMap::new(0, 0x0010_0000),
        addrs: Vec::new(),
        forward: true,
    };
    wv_perf!(
        "Freeing 100 areas forward",
        prof.runner::<CycleInstant, _>(&mut tester)
    );

    tester.forward = false;
    wv_perf!(
        "Freeing 100 areas backwards",
        prof.runner::<CycleInstant, _>(&mut tester)
    );
}
