/*
 * Copyright (C) 2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
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

#[macro_use]
extern crate m3;

use m3::mem::heap;
use m3::test::Tester;
use m3::vfs::VFS;

mod tboxlist;
mod tbufio;
mod tdir;
mod tdlist;
mod tfilemux;
mod tgenfile;
mod tm3fs;
mod tmemmap;
mod tmgate;
mod tpipe;
mod trgate;
mod tserver;
mod tsgate;
mod tsyscalls;
mod ttreap;
mod tvpe;

struct MyTester {
}

impl Tester for MyTester {
    fn run_suite(&mut self, name: &str, f: &Fn(&mut Tester)) {
        println!("Running test suite {} ...", name);
        f(self);
        println!("Done\n");
    }

    fn run_test(&mut self, name: &str, f: &Fn()) {
        println!("-- Running test {} ...", name);
        let free_mem = heap::free_memory();
        f();
        assert_eq!(heap::free_memory(), free_mem);
        println!("-- Done");
    }
}

#[no_mangle]
pub fn main() -> i32 {
    // do a mount here to ensure that we don't need to realloc the mount-table later, which screws
    // up our simple memory-leak detection above
    assert_ok!(VFS::mount("/fs/", "m3fs"));
    assert_ok!(VFS::unmount("/fs/"));

    let mut tester = MyTester {};
    run_suite!(tester, tboxlist::run);
    run_suite!(tester, tbufio::run);
    run_suite!(tester, tdir::run);
    run_suite!(tester, tdlist::run);
    run_suite!(tester, tfilemux::run);
    run_suite!(tester, tgenfile::run);
    run_suite!(tester, tm3fs::run);
    run_suite!(tester, tmemmap::run);
    run_suite!(tester, tmgate::run);
    run_suite!(tester, tpipe::run);
    run_suite!(tester, trgate::run);
    run_suite!(tester, tsgate::run);
    run_suite!(tester, tserver::run);
    run_suite!(tester, tsyscalls::run);
    run_suite!(tester, ttreap::run);
    run_suite!(tester, tvpe::run);

    println!("\x1B[1;32mAll tests successful!\x1B[0;m");
    0
}
