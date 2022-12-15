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

use m3::cell::StaticCell;
use m3::cfg;
use m3::com::{MemGate, Perm, RecvGate};
use m3::goff;
use m3::kif;
use m3::math;
use m3::rc::Rc;
use m3::syscalls;
use m3::test::WvTester;
use m3::tiles::{Activity, ActivityArgs, ChildActivity, Tile};
use m3::time::{CycleInstant, Profiler, Runner};
use m3::{println, wv_assert_ok, wv_perf, wv_run_test};

static SEL: StaticCell<kif::CapSel> = StaticCell::new(0);

pub fn run(t: &mut dyn WvTester) {
    SEL.set(Activity::own().alloc_sel());

    wv_run_test!(t, noop);
    wv_run_test!(t, activate);
    wv_run_test!(t, create_mgate);
    wv_run_test!(t, create_rgate);
    wv_run_test!(t, create_sgate);
    wv_run_test!(t, create_map);
    wv_run_test!(t, create_srv);
    wv_run_test!(t, derive_mem);
    wv_run_test!(t, exchange);
    wv_run_test!(t, revoke_mem_gate);
    wv_run_test!(t, revoke_recv_gate);
    wv_run_test!(t, revoke_send_gate);
}

fn noop(_t: &mut dyn WvTester) {
    let prof = Profiler::default();

    wv_perf!(
        "noop",
        prof.run::<CycleInstant, _>(|| {
            wv_assert_ok!(syscalls::noop());
        })
    );
}

fn activate(_t: &mut dyn WvTester) {
    let mgate = wv_assert_ok!(MemGate::new(0x1000, Perm::RW));
    let ep = wv_assert_ok!(Activity::own().epmng_mut().acquire(0));

    let prof = Profiler::default();

    wv_perf!(
        "activate",
        prof.run::<CycleInstant, _>(|| {
            wv_assert_ok!(syscalls::activate(
                ep.sel(),
                mgate.sel(),
                kif::INVALID_SEL,
                0
            ));
        })
    );

    Activity::own().epmng_mut().release(ep, true);
}

fn create_mgate(_t: &mut dyn WvTester) {
    let prof = Profiler::default().repeats(100).warmup(100);

    #[derive(Default)]
    struct Tester(usize);

    impl Runner for Tester {
        fn run(&mut self) {
            wv_assert_ok!(syscalls::create_mgate(
                SEL.get(),
                Activity::own().sel(),
                self.0 as goff,
                cfg::PAGE_SIZE as goff,
                Perm::R
            ));
        }

        fn post(&mut self) {
            wv_assert_ok!(syscalls::revoke(
                Activity::own().sel(),
                kif::CapRngDesc::new(kif::CapType::OBJECT, SEL.get(), 1),
                true
            ));
        }
    }

    let addr: usize = math::round_dn(&create_mgate as *const _ as usize, cfg::PAGE_SIZE);
    wv_perf!(
        "create_mgate",
        prof.runner::<CycleInstant, _>(&mut Tester(addr))
    );
}

fn create_rgate(_t: &mut dyn WvTester) {
    let prof = Profiler::default().repeats(100).warmup(100);

    #[derive(Default)]
    struct Tester();

    impl Runner for Tester {
        fn run(&mut self) {
            wv_assert_ok!(syscalls::create_rgate(SEL.get(), 10, 10));
        }

        fn post(&mut self) {
            wv_assert_ok!(syscalls::revoke(
                Activity::own().sel(),
                kif::CapRngDesc::new(kif::CapType::OBJECT, SEL.get(), 1),
                true
            ));
        }
    }

    wv_perf!(
        "create_rgate",
        prof.runner::<CycleInstant, _>(&mut Tester::default())
    );
}

fn create_sgate(_t: &mut dyn WvTester) {
    let prof = Profiler::default().repeats(100).warmup(10);

    #[derive(Default)]
    struct Tester(Option<RecvGate>);

    impl Runner for Tester {
        fn pre(&mut self) {
            if self.0.is_none() {
                self.0 = Some(wv_assert_ok!(RecvGate::new(10, 10)));
            }
        }

        fn run(&mut self) {
            wv_assert_ok!(syscalls::create_sgate(
                SEL.get(),
                self.0.as_ref().unwrap().sel(),
                0x1234,
                1024
            ));
        }

        fn post(&mut self) {
            wv_assert_ok!(syscalls::revoke(
                Activity::own().sel(),
                kif::CapRngDesc::new(kif::CapType::OBJECT, SEL.get(), 1),
                true
            ));
        }
    }

    wv_perf!(
        "create_sgate",
        prof.runner::<CycleInstant, _>(&mut Tester::default())
    );
}

fn create_map(_t: &mut dyn WvTester) {
    if !Activity::own().tile_desc().has_virtmem() {
        println!("Tile has no virtual memory support; skipping");
        return;
    }

    const DEST: kif::CapSel = 0x3000_0000 >> cfg::PAGE_BITS;
    let prof = Profiler::default().repeats(100).warmup(10);

    struct Tester(MemGate);

    impl Runner for Tester {
        fn pre(&mut self) {
            // one warmup run, because the revoke leads to an unmap, which flushes and invalidates
            // all cache lines
            wv_assert_ok!(syscalls::create_map(
                DEST,
                Activity::own().sel(),
                self.0.sel(),
                0,
                1,
                Perm::RW
            ));
        }

        fn run(&mut self) {
            wv_assert_ok!(syscalls::create_map(
                DEST + 1,
                Activity::own().sel(),
                self.0.sel(),
                1,
                1,
                Perm::RW
            ));
        }

        fn post(&mut self) {
            wv_assert_ok!(syscalls::revoke(
                Activity::own().sel(),
                kif::CapRngDesc::new(kif::CapType::MAPPING, DEST, 2),
                true
            ));
        }
    }

    let mut tester = Tester(MemGate::new(cfg::PAGE_SIZE * 2, Perm::RW).unwrap());
    wv_perf!("create_map", prof.runner::<CycleInstant, _>(&mut tester));
}

fn create_srv(_t: &mut dyn WvTester) {
    let prof = Profiler::default().repeats(100).warmup(10);

    #[derive(Default)]
    struct Tester(Option<RecvGate>);

    impl Runner for Tester {
        fn pre(&mut self) {
            if self.0.is_none() {
                self.0 = Some(wv_assert_ok!(RecvGate::new(10, 10)));
                self.0.as_mut().unwrap().activate().unwrap();
            }
        }

        fn run(&mut self) {
            wv_assert_ok!(syscalls::create_srv(
                SEL.get(),
                self.0.as_ref().unwrap().sel(),
                "test",
                0
            ));
        }

        fn post(&mut self) {
            wv_assert_ok!(syscalls::revoke(
                Activity::own().sel(),
                kif::CapRngDesc::new(kif::CapType::OBJECT, SEL.get(), 1),
                true
            ));
        }
    }

    wv_perf!(
        "create_srv",
        prof.runner::<CycleInstant, _>(&mut Tester::default())
    );
}

fn derive_mem(_t: &mut dyn WvTester) {
    let prof = Profiler::default().repeats(100).warmup(10);

    #[derive(Default)]
    struct Tester(Option<MemGate>);

    impl Runner for Tester {
        fn pre(&mut self) {
            if self.0.is_none() {
                self.0 = Some(wv_assert_ok!(MemGate::new(0x1000, Perm::RW)));
            }
        }

        fn run(&mut self) {
            wv_assert_ok!(syscalls::derive_mem(
                Activity::own().sel(),
                SEL.get(),
                self.0.as_ref().unwrap().sel(),
                0,
                0x1000,
                Perm::RW
            ));
        }

        fn post(&mut self) {
            wv_assert_ok!(syscalls::revoke(
                Activity::own().sel(),
                kif::CapRngDesc::new(kif::CapType::OBJECT, SEL.get(), 1),
                true
            ));
        }
    }

    wv_perf!(
        "derive_mem",
        prof.runner::<CycleInstant, _>(&mut Tester::default())
    );
}

fn exchange(_t: &mut dyn WvTester) {
    let prof = Profiler::default().repeats(100).warmup(10);

    struct Tester {
        act: Option<ChildActivity>,
        tile: Rc<Tile>,
    }

    impl Runner for Tester {
        fn pre(&mut self) {
            if self.act.is_none() {
                self.act = Some(wv_assert_ok!(ChildActivity::new_with(
                    self.tile.clone(),
                    ActivityArgs::new("test")
                )));
            }
        }

        fn run(&mut self) {
            wv_assert_ok!(syscalls::exchange(
                self.act.as_ref().unwrap().sel(),
                kif::CapRngDesc::new(kif::CapType::OBJECT, kif::SEL_ACT, 1),
                SEL.get(),
                false,
            ));
        }

        fn post(&mut self) {
            wv_assert_ok!(syscalls::revoke(
                self.act.as_ref().unwrap().sel(),
                kif::CapRngDesc::new(kif::CapType::OBJECT, SEL.get(), 1),
                true
            ));
        }
    }

    wv_perf!(
        "exchange",
        prof.runner::<CycleInstant, _>(&mut Tester {
            act: None,
            tile: wv_assert_ok!(Tile::get("clone|own")),
        })
    );
}

fn revoke_mem_gate(_t: &mut dyn WvTester) {
    let prof = Profiler::default().repeats(100).warmup(10);

    let mgate = wv_assert_ok!(MemGate::new(0x1000, Perm::RW));

    struct Tester {
        mgate: MemGate,
        _derived: Option<MemGate>,
    }

    impl Runner for Tester {
        fn pre(&mut self) {
            self._derived = Some(wv_assert_ok!(self.mgate.derive(0, 0x1000, Perm::RW)));
        }

        fn run(&mut self) {
            self._derived = None;
        }
    }

    let mut tester = Tester {
        mgate,
        _derived: None,
    };
    wv_perf!(
        "revoke_mem_gate",
        prof.runner::<CycleInstant, _>(&mut tester)
    );
}

fn revoke_recv_gate(_t: &mut dyn WvTester) {
    let prof = Profiler::default().repeats(100).warmup(10);

    #[derive(Default)]
    struct Tester();

    impl Runner for Tester {
        fn pre(&mut self) {
            wv_assert_ok!(syscalls::create_rgate(SEL.get(), 10, 10));
        }

        fn run(&mut self) {
            wv_assert_ok!(syscalls::revoke(
                Activity::own().sel(),
                kif::CapRngDesc::new(kif::CapType::OBJECT, SEL.get(), 1),
                true
            ));
        }
    }

    wv_perf!(
        "revoke_recv_gate",
        prof.runner::<CycleInstant, _>(&mut Tester::default())
    );
}

fn revoke_send_gate(_t: &mut dyn WvTester) {
    let prof = Profiler::default().repeats(100).warmup(10);

    #[derive(Default)]
    struct Tester(Option<RecvGate>);

    impl Runner for Tester {
        fn pre(&mut self) {
            self.0 = Some(wv_assert_ok!(RecvGate::new(10, 10)));
            wv_assert_ok!(syscalls::create_sgate(
                SEL.get(),
                self.0.as_ref().unwrap().sel(),
                0x1234,
                1024
            ));
        }

        fn run(&mut self) {
            wv_assert_ok!(syscalls::revoke(
                Activity::own().sel(),
                kif::CapRngDesc::new(kif::CapType::OBJECT, SEL.get(), 1),
                true
            ));
        }
    }

    wv_perf!(
        "revoke_send_gate",
        prof.runner::<CycleInstant, _>(&mut Tester::default())
    );
}
