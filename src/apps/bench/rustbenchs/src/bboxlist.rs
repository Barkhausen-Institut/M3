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

use m3::boxed::Box;
use m3::col::{BoxList, BoxRef};
use m3::mem;
use m3::test::WvTester;
use m3::time::{CycleInstant, Profiler, Runner};
use m3::{impl_boxitem, wv_perf, wv_run_test};

#[derive(Default, Clone)]
struct TestItem {
    _data: u32,
    prev: Option<BoxRef<TestItem>>,
    next: Option<BoxRef<TestItem>>,
}

impl_boxitem!(TestItem);

impl TestItem {
    pub fn new(data: u32) -> Self {
        TestItem {
            _data: data,
            prev: None,
            next: None,
        }
    }
}

pub fn run(t: &mut dyn WvTester) {
    wv_run_test!(t, push_back);
    wv_run_test!(t, push_front);
    wv_run_test!(t, push_pop);
    wv_run_test!(t, clear);
}

fn push_back(_t: &mut dyn WvTester) {
    let prof = Profiler::default().warmup(100).repeats(30);

    #[derive(Default)]
    struct ListTester(BoxList<TestItem>);

    impl Runner for ListTester {
        fn pre(&mut self) {
            self.0.clear();
        }

        fn run(&mut self) {
            for i in 0..10 {
                self.0.push_back(Box::new(TestItem::new(i)));
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
    struct ListTester(BoxList<TestItem>);

    impl Runner for ListTester {
        fn pre(&mut self) {
            self.0.clear();
        }

        fn run(&mut self) {
            for i in 0..10 {
                self.0.push_front(Box::new(TestItem::new(i)));
            }
        }
    }

    wv_perf!(
        "Prepending 10 elements",
        prof.runner::<CycleInstant, _>(&mut ListTester::default())
    );
}

fn push_pop(_t: &mut dyn WvTester) {
    let prof = Profiler::default().repeats(30);

    #[derive(Default)]
    struct ListTester(BoxList<TestItem>, Option<Box<TestItem>>, usize);

    impl Runner for ListTester {
        fn pre(&mut self) {
            self.1 = Some(Box::new(TestItem::new(213)));
        }

        fn run(&mut self) {
            let item = mem::replace(&mut self.1, None);
            self.0.push_front(item.unwrap());
        }

        fn post(&mut self) {
            self.2 += 1;
            assert!(self.0.len() == self.2);
        }
    }

    wv_perf!(
        "Prepending 1 element",
        prof.runner::<CycleInstant, _>(&mut ListTester::default())
    );
}

fn clear(_t: &mut dyn WvTester) {
    let prof = Profiler::default().warmup(100).repeats(30);

    #[derive(Default)]
    struct ListTester(BoxList<TestItem>);

    impl Runner for ListTester {
        fn pre(&mut self) {
            for i in 0..10 {
                self.0.push_back(Box::new(TestItem::new(i)));
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
