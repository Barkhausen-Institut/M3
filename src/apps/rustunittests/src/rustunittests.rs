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

#![no_std]

use m3::cell::StaticCell;
use m3::test::WvTester;
use m3::{println, wv_run_suite};

mod tactivity;
mod tboxlist;
mod tbufio;
mod tdir;
mod tdlist;
mod tenvvars;
mod tfilemux;
mod tfloat;
mod tgenfile;
mod tm3fs;
mod tmemmap;
mod tmgate;
mod tnonblock;
mod tpaging;
mod tpipe;
mod trgate;
mod tsems;
mod tserver;
mod tsgate;
#[cfg(not(target_vendor = "host"))]
mod tsrvmsgs;
mod tsyscalls;
mod ttreap;

// TODO that's hacky, but the only alternative I can see is to pass the WvTester to every single
// test case and every single wv_assert_* call, which is quite inconvenient.
static FAILED: StaticCell<u32> = StaticCell::new(0);

extern "C" fn wvtest_failed() {
    FAILED.set(FAILED.get() + 1);
}

struct MyTester {}

impl WvTester for MyTester {
    fn run_suite(&mut self, name: &str, f: &dyn Fn(&mut dyn WvTester)) {
        println!("Running test suite {} ...\n", name);
        f(self);
        println!();
    }

    fn run_test(&mut self, name: &str, file: &str, f: &dyn Fn()) {
        println!("Testing \"{}\" in {}:", name, file);
        f();
        println!();
    }
}

#[no_mangle]
pub fn main() -> i32 {
    let mut tester = MyTester {};
    wv_run_suite!(tester, tboxlist::run);
    wv_run_suite!(tester, tbufio::run);
    wv_run_suite!(tester, tdir::run);
    wv_run_suite!(tester, tdlist::run);
    wv_run_suite!(tester, tenvvars::run);
    wv_run_suite!(tester, tfilemux::run);
    wv_run_suite!(tester, tfloat::run);
    wv_run_suite!(tester, tgenfile::run);
    wv_run_suite!(tester, tm3fs::run);
    wv_run_suite!(tester, tmemmap::run);
    wv_run_suite!(tester, tmgate::run);
    wv_run_suite!(tester, tnonblock::run);
    wv_run_suite!(tester, tpaging::run);
    wv_run_suite!(tester, tpipe::run);
    wv_run_suite!(tester, trgate::run);
    wv_run_suite!(tester, tsgate::run);
    wv_run_suite!(tester, tsems::run);
    wv_run_suite!(tester, tserver::run);
    // requires a TileMux with notification support
    #[cfg(not(target_vendor = "host"))]
    wv_run_suite!(tester, tsrvmsgs::run);
    wv_run_suite!(tester, tsyscalls::run);
    wv_run_suite!(tester, ttreap::run);
    wv_run_suite!(tester, tactivity::run);

    if FAILED.get() > 0 {
        println!("\x1B[1;31m{} tests failed\x1B[0;m", FAILED.get());
    }
    else {
        println!("\x1B[1;32mAll tests successful!\x1B[0;m");
    }
    0
}
