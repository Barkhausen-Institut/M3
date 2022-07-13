/*
 * Copyright (C) 2023 Nils Asmussen, Barkhausen Institut
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
use m3::com::{MemGate, RGateArgs, RecvGate};
use m3::errors::{Code, Error, VerboseError};
use m3::kif::Perm;
use m3::test::WvTester;
use m3::tiles::{ActivityArgs, ChildActivity, RunningActivity, RunningDeviceActivity, Tile};
use m3::{wv_assert_eq, wv_assert_ok};

use resmng::childs::{Child, ChildManager, OwnChild};
use resmng::config::Domain;
use resmng::requests::Requests;
use resmng::resources::{tiles::TileUsage, Resources};
use resmng::subsys::{ChildStarter, Subsystem, SubsystemBuilder};

pub struct TestStarter {}
impl ChildStarter for TestStarter {
    fn start_async(
        &mut self,
        _reqs: &Requests,
        _res: &mut Resources,
        child: &mut OwnChild,
    ) -> Result<(), VerboseError> {
        let act = wv_assert_ok!(ChildActivity::new(
            child.child_tile().unwrap().tile_obj().clone(),
            child.name(),
        ));

        let run = RunningDeviceActivity::new(act);
        child.set_running(Box::new(run));

        Ok(())
    }

    fn configure_tile(
        &mut self,
        _res: &mut Resources,
        _tile: &mut TileUsage,
        _dom: &Domain,
    ) -> Result<(), VerboseError> {
        Ok(())
    }
}

pub fn run_subsys<F>(
    t: &mut dyn WvTester,
    cfg: &str,
    customize_subsys: F,
    func: fn() -> Result<(), Error>,
) where
    F: Fn(&mut SubsystemBuilder),
{
    let tile = wv_assert_ok!(Tile::get("compat|own"));
    let mut child = wv_assert_ok!(ChildActivity::new_with(
        tile.clone(),
        ActivityArgs::new("test").first_sel(1000)
    ));

    let (_our_sub, mut res) = wv_assert_ok!(Subsystem::new());
    let mut child_sub = SubsystemBuilder::default();

    wv_assert_ok!(child_sub.add_config(cfg, |size| MemGate::new(size, Perm::RW)));
    let tile_quota = wv_assert_ok!(tile.quota());
    child_sub.add_tile(wv_assert_ok!(tile.derive(
        Some(tile_quota.endpoints().remaining() / 2),
        None,
        Some(tile_quota.time().remaining() / 2),
        Some(tile_quota.page_tables().remaining() / 2)
    )));
    let mux = "tilemux";
    let mux_mod = wv_assert_ok!(MemGate::new_bind_bootmod(mux));
    child_sub.add_mod(mux_mod, mux);
    let sub_mem = wv_assert_ok!(res.memory_mut().alloc_mem(64 * 1024 * 1024));
    child_sub.add_mem(wv_assert_ok!(sub_mem.derive()), false);
    customize_subsys(&mut child_sub);

    wv_assert_ok!(child_sub.finalize_async(&mut res, 0, &mut child));

    let run = wv_assert_ok!(child.run(func));

    wv_assert_eq!(t, run.wait(), Ok(Code::Success));
}

pub fn setup_resmng() -> (Requests, ChildManager, Subsystem, Resources) {
    let req_rgate = wv_assert_ok!(RecvGate::new_with(
        RGateArgs::default().order(6).msg_order(6),
    ));
    let reqs = Requests::new(req_rgate);

    let childs = ChildManager::default();

    let (child_sub, res) = wv_assert_ok!(Subsystem::new());

    (reqs, childs, child_sub, res)
}
