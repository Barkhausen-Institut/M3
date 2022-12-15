/*
 * Copyright (C) 2021, Stephan Gerhold <stephan.gerhold@mailbox.tu-dresden.de>
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

use crate::util;
use m3::com::{MemGate, Perm};
use m3::crypto::HashAlgorithm;
use m3::session::{HashInput, HashOutput, HashSession};
use m3::test::WvTester;
use m3::time::{CycleInstant, Duration, Profiler};
use m3::vfs::{OpenFlags, VFS};
use m3::{format, vec, wv_assert_ok, wv_perf, wv_run_test};

pub fn run(t: &mut dyn WvTester) {
    wv_run_test!(t, reset);
    wv_run_test!(t, hash_empty);
    wv_run_test!(t, hash_mem);
    wv_run_test!(t, hash_mem_sizes);
    wv_run_test!(t, hash_file);
    wv_run_test!(t, shake_mem);
    wv_run_test!(t, shake_mem_sizes);
    wv_run_test!(t, shake_file);
}

fn reset(_t: &mut dyn WvTester) {
    let prof = Profiler::default();
    let mut hash = wv_assert_ok!(HashSession::new("hash-bench", &HashAlgorithm::SHA3_256));

    wv_perf!(
        "reset hash",
        prof.run::<CycleInstant, _>(|| wv_assert_ok!(hash.reset(&HashAlgorithm::SHA3_256)))
    );
}

fn hash_empty(_t: &mut dyn WvTester) {
    let prof = Profiler::default();
    for algo in HashAlgorithm::ALL.iter() {
        if algo.is_xof() {
            continue;
        }

        let mut hash = wv_assert_ok!(HashSession::new("hash-bench", algo));
        let mut result = vec![0u8; algo.output_bytes];
        wv_perf!(
            format!("hash reset + finish with {}", algo.name),
            prof.run::<CycleInstant, _>(|| {
                wv_assert_ok!(hash.reset(algo));
                wv_assert_ok!(hash.finish(&mut result));
            })
        );
    }
}

fn _prepare_hash_mem(size: usize) -> (MemGate, MemGate) {
    let mgate = util::prepare_shake_mem(size);
    let mgated = wv_assert_ok!(mgate.derive(0, size, Perm::R));
    (mgate, mgated)
}

fn hash_mem(_t: &mut dyn WvTester) {
    const SIZE: usize = 512 * 1024; // 512 KiB

    let (_mgate, mgated) = _prepare_hash_mem(SIZE);
    let prof = Profiler::default().warmup(2).repeats(5);

    for algo in HashAlgorithm::ALL.iter() {
        let hash = wv_assert_ok!(HashSession::new("hash-bench", algo));
        wv_assert_ok!(hash.ep().configure(mgated.sel()));

        let res = prof.run::<CycleInstant, _>(|| {
            wv_assert_ok!(hash.input(0, SIZE));
        });

        wv_perf!(
            format!("hash {} bytes with {}", SIZE, algo.name),
            format!(
                "{}; throughput {:.8} bytes/cycle",
                res,
                SIZE as f32 / res.avg().as_raw() as f32
            )
        );
    }
}

const TEST_ALGO: &HashAlgorithm = &HashAlgorithm::SHA3_256;

fn hash_mem_sizes(_t: &mut dyn WvTester) {
    const MAX_SIZE_SHIFT: usize = 19; // 2^19 = 512 KiB
    const MAX_SIZE: usize = 1 << MAX_SIZE_SHIFT;

    let (_mgate, mgated) = _prepare_hash_mem(MAX_SIZE);
    let mut prof = Profiler::default().warmup(5).repeats(15);

    for shift in 0..=MAX_SIZE_SHIFT {
        let hash = wv_assert_ok!(HashSession::new("hash-bench", TEST_ALGO));
        wv_assert_ok!(hash.ep().configure(mgated.sel()));

        let size = 1usize << shift;
        if shift == 14 {
            prof = prof.warmup(2).repeats(5); // 2^14 = 16 KiB
        }

        let res = prof.run::<CycleInstant, _>(|| {
            wv_assert_ok!(hash.input(0, size));
        });

        wv_perf!(
            format!("hash {} bytes with {}", size, TEST_ALGO.name),
            format!(
                "{}; throughput {:.8} bytes/cycle",
                res,
                size as f32 / res.avg().as_raw() as f32
            )
        );
    }
}

fn hash_file(_t: &mut dyn WvTester) {
    const SIZE: usize = 512 * 1024; // 512 KiB

    {
        // Fill file with pseudo random data using SHAKE
        let hash = wv_assert_ok!(HashSession::new("hash-prepare", &HashAlgorithm::SHAKE128));
        let mut file = wv_assert_ok!(VFS::open(
            "/shake.bin",
            OpenFlags::W | OpenFlags::CREATE | OpenFlags::NEW_SESS
        ));
        wv_assert_ok!(file.hash_output(&hash, SIZE));
    }

    let prof = Profiler::default().warmup(2).repeats(5);

    for algo in HashAlgorithm::ALL.iter() {
        let hash = wv_assert_ok!(HashSession::new("hash-bench", algo));
        let res = prof.run::<CycleInstant, _>(|| {
            let mut file =
                wv_assert_ok!(VFS::open("/shake.bin", OpenFlags::R | OpenFlags::NEW_SESS));
            wv_assert_ok!(file.hash_input(&hash, usize::MAX));
        });

        wv_perf!(
            format!("hash file ({} bytes) with {}", SIZE, algo.name),
            format!(
                "{}; throughput {:.8} bytes/cycle",
                res,
                SIZE as f32 / res.avg().as_raw() as f32
            )
        );
    }
}

fn _prepare_shake_mem(size: usize) -> (MemGate, MemGate) {
    let mgate = wv_assert_ok!(MemGate::new(size, Perm::RW));
    let mgated = wv_assert_ok!(mgate.derive(0, size, Perm::W));
    (mgate, mgated)
}

fn shake_mem(_t: &mut dyn WvTester) {
    const SIZE: usize = 512 * 1024; // 512 KiB

    let (_mgate, mgated) = _prepare_shake_mem(SIZE);
    let prof = Profiler::default().warmup(2).repeats(5);

    for algo in HashAlgorithm::ALL.iter() {
        if !algo.is_xof() {
            continue;
        }

        let hash = wv_assert_ok!(HashSession::new("hash-bench", algo));
        wv_assert_ok!(hash.ep().configure(mgated.sel()));

        let res = prof.run::<CycleInstant, _>(|| {
            wv_assert_ok!(hash.output(0, SIZE));
        });

        wv_perf!(
            format!("shake {} bytes with {}", SIZE, algo.name),
            format!(
                "{}; throughput {:.8} bytes/cycle",
                res,
                SIZE as f32 / res.avg().as_raw() as f32
            )
        );
    }
}

const SHAKE_TEST_ALGO: &HashAlgorithm = &HashAlgorithm::SHAKE128;

fn shake_mem_sizes(_t: &mut dyn WvTester) {
    const MAX_SIZE_SHIFT: usize = 19; // 2^19 = 512 KiB
    const MAX_SIZE: usize = 1 << MAX_SIZE_SHIFT;

    let (_mgate, mgated) = _prepare_shake_mem(MAX_SIZE);
    let mut prof = Profiler::default().warmup(5).repeats(15);

    for shift in 0..=MAX_SIZE_SHIFT {
        let size = 1usize << shift;
        if shift == 14 {
            prof = prof.warmup(2).repeats(5); // 2^14 = 16 KiB
        }

        let hash = wv_assert_ok!(HashSession::new("hash-bench", SHAKE_TEST_ALGO));
        wv_assert_ok!(hash.ep().configure(mgated.sel()));

        let res = prof.run::<CycleInstant, _>(|| {
            wv_assert_ok!(hash.output(0, size));
        });

        wv_perf!(
            format!("shake {} bytes with {}", size, SHAKE_TEST_ALGO.name),
            format!(
                "{}; throughput {:.8} bytes/cycle",
                res,
                size as f32 / res.avg().as_raw() as f32
            )
        );
    }
}

fn shake_file(_t: &mut dyn WvTester) {
    const SIZE: usize = 512 * 1024; // 512 KiB

    let prof = Profiler::default().warmup(2).repeats(5);

    for algo in HashAlgorithm::ALL.iter() {
        if !algo.is_xof() {
            continue;
        }

        let hash = wv_assert_ok!(HashSession::new("hash-bench", algo));
        let res = prof.run::<CycleInstant, _>(|| {
            let mut file =
                wv_assert_ok!(VFS::open("/shake.bin", OpenFlags::W | OpenFlags::NEW_SESS));
            wv_assert_ok!(file.hash_output(&hash, SIZE));
        });

        wv_perf!(
            format!("shake file ({} bytes) with {}", SIZE, algo.name),
            format!(
                "{}; throughput {:.8} bytes/cycle",
                res,
                SIZE as f32 / res.avg().as_raw() as f32
            )
        );
    }
}
