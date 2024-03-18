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

use m3::test::WvTester;

pub fn run(_t: &mut dyn WvTester) {
    #[cfg(not(target_arch = "riscv32"))]
    {
        use m3::wv_run_test;
        wv_run_test!(_t, basics);
    }
}

// TODO time-related functions are currently not supported for riscv32, because rust-std thinks
// time_t is a 32-bit integer, while musl defines it as a 64-bit integer. I assume this is because
// we tell rust-std that we have glibc instead of musl (which we have to, because rust-std + RISCV
// + musl is not supported at all).
#[cfg(not(target_arch = "riscv32"))]
fn basics(t: &mut dyn WvTester) {
    use m3::wv_assert;

    use std::thread::sleep;
    use std::time::{Duration, Instant};

    let instant = Instant::now();
    let three_millis = Duration::from_millis(3);
    sleep(three_millis);
    wv_assert!(t, instant.elapsed() >= three_millis);
}
