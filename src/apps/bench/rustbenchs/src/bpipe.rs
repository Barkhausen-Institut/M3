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

use m3::cell::StaticRefCell;
use m3::com::MemGate;
use m3::io::{self, Read, Write};
use m3::kif;
use m3::mem::AlignedBuf;
use m3::session::Pipes;
use m3::test::WvTester;
use m3::tiles::{Activity, ActivityArgs, ChildActivity, RunningActivity, Tile};
use m3::time::{CycleInstant, Profiler};
use m3::vfs::IndirectPipe;
use m3::{format, wv_assert_eq, wv_assert_ok, wv_perf, wv_run_test};

const DATA_SIZE: usize = 2 * 1024 * 1024;
const BUF_SIZE: usize = 8 * 1024;

static BUF: StaticRefCell<AlignedBuf<BUF_SIZE>> = StaticRefCell::new(AlignedBuf::new_zeroed());

pub fn run(t: &mut dyn WvTester) {
    wv_run_test!(t, child_to_parent);
    wv_run_test!(t, parent_to_child);
}

fn child_to_parent(t: &mut dyn WvTester) {
    let pipeserv = wv_assert_ok!(Pipes::new("pipes"));
    let prof = Profiler::default().repeats(2).warmup(1);

    let tile = wv_assert_ok!(Tile::get("clone|own"));
    let res = prof.run::<CycleInstant, _>(|| {
        let pipe_mem = wv_assert_ok!(MemGate::new(0x10000, kif::Perm::RW));
        let pipe = wv_assert_ok!(IndirectPipe::new(&pipeserv, &pipe_mem, 0x10000));

        let mut act = wv_assert_ok!(ChildActivity::new_with(
            tile.clone(),
            ActivityArgs::new("writer")
        ));
        act.add_file(io::STDOUT_FILENO, pipe.writer().unwrap().fd());

        let act = wv_assert_ok!(act.run(|| {
            let mut output = Activity::own().files().get(io::STDOUT_FILENO).unwrap();
            let buf = BUF.borrow();
            let mut rem = DATA_SIZE;
            while rem > 0 {
                wv_assert_ok!(output.write(&buf[..]));
                rem -= BUF_SIZE;
            }
            0
        }));

        pipe.close_writer();

        let mut input = pipe.reader().unwrap();
        let mut buf = BUF.borrow_mut();
        while wv_assert_ok!(input.read(&mut buf[..])) > 0 {}

        wv_assert_eq!(t, act.wait(), Ok(0));
    });

    wv_perf!(
        format!(
            "c->p: {} KiB transfer with {} KiB buf",
            DATA_SIZE / 1024,
            BUF_SIZE / 1024
        ),
        res
    );
}

fn parent_to_child(t: &mut dyn WvTester) {
    let pipeserv = wv_assert_ok!(Pipes::new("pipes"));
    let prof = Profiler::default().repeats(2).warmup(1);

    let tile = wv_assert_ok!(Tile::get("clone|own"));
    let res = prof.run::<CycleInstant, _>(|| {
        let pipe_mem = wv_assert_ok!(MemGate::new(0x10000, kif::Perm::RW));
        let pipe = wv_assert_ok!(IndirectPipe::new(&pipeserv, &pipe_mem, 0x10000));

        let mut act = wv_assert_ok!(ChildActivity::new_with(
            tile.clone(),
            ActivityArgs::new("reader")
        ));
        act.add_file(io::STDIN_FILENO, pipe.reader().unwrap().fd());

        let act = wv_assert_ok!(act.run(|| {
            let mut input = Activity::own().files().get(io::STDIN_FILENO).unwrap();
            let mut buf = BUF.borrow_mut();
            while wv_assert_ok!(input.read(&mut buf[..])) > 0 {}
            0
        }));

        pipe.close_reader();

        let mut output = pipe.writer().unwrap();
        let buf = BUF.borrow();
        let mut rem = DATA_SIZE;
        while rem > 0 {
            wv_assert_ok!(output.write(&buf[..]));
            rem -= BUF_SIZE;
        }

        pipe.close_writer();

        wv_assert_eq!(t, act.wait(), Ok(0));
    });

    wv_perf!(
        format!(
            "p->c: {} KiB transfer with {} KiB buf",
            DATA_SIZE / 1024,
            BUF_SIZE / 1024
        ),
        res
    );
}
