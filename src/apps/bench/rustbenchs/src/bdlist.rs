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

use m3::col::DList;
use m3::test::WvTester;
use m3::time::{CycleInstant, Profiler, Runner};
use m3::{wv_perf, wv_run_test};

pub fn run(t: &mut dyn WvTester) {
    wv_run_test!(t, push_back);
    wv_run_test!(t, push_front);
    wv_run_test!(t, clear);
}

fn push_back(_t: &mut dyn WvTester) {
    let prof = Profiler::default().warmup(100).repeats(30);

    #[derive(Default)]
    struct ListTester(DList<u32>);

    impl Runner for ListTester {
        fn pre(&mut self) {
            self.0.clear();
        }

        fn run(&mut self) {
            for i in 0..10 {
                self.0.push_back(i);
            }
        }
    }

    wv_perf!(
        "Appending 10 elements",
        prof.runner::<CycleInstant, _>(&mut ListTester::default())
    );
}

fn push_front(_t: &mut dyn WvTester) {
    let prof = Profiler::default().warmup(100).repeats(30);

    #[derive(Default)]
    struct ListTester(DList<u32>);

    impl Runner for ListTester {
        fn pre(&mut self) {
            self.0.clear();
        }

        fn run(&mut self) {
            for i in 0..10 {
                self.0.push_front(i);
            }
        }
    }

    wv_perf!(
        "Prepending 10 elements",
        prof.runner::<CycleInstant, _>(&mut ListTester::default())
    );
}

fn clear(_t: &mut dyn WvTester) {
    let prof = Profiler::default().warmup(100).repeats(30);

    #[derive(Default)]
    struct ListTester(DList<u32>);

    impl Runner for ListTester {
        fn pre(&mut self) {
            for i in 0..10 {
                self.0.push_back(i);
            }
        }

        fn run(&mut self) {
            self.0.clear();
        }
    }

    wv_perf!(
        "Clearing 10-element list",
        prof.runner::<CycleInstant, _>(&mut ListTester::default())
    );
}
