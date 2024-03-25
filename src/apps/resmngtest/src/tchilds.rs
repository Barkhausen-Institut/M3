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

use m3::col::ToString;
use m3::errors::Code;
use m3::kif::{Perm, TileDesc, TileISA, TileType};
use m3::mem::GlobOff;
use m3::test::{DefaultWvTester, WvTester};
use m3::tiles::{Activity, Tile};
use m3::{wv_assert_eq, wv_assert_err, wv_assert_ok, wv_assert_some, wv_run_test};

use resmng::childs::Child;
use resmng::resources::Resources;
use resmng::subsys::Subsystem;

use crate::helper::{run_subsys, setup_resmng, TestStarter};

pub fn run(t: &mut dyn WvTester) {
    wv_run_test!(t, basics);
}

fn basics(t: &mut dyn WvTester) {
    run_subsys(
        t,
        "<app args=\"resmngtest\">
             <dom>
                 <app args=\"/bin/rusthello\" usermem=\"32M\">
                    <serv name=\"test\" />
                    <tiles type=\"core\" count=\"1\"/>
                 </app>
             </dom>
         </app>",
        |subsys| {
            subsys.add_tile(wv_assert_ok!(Tile::get("clone")));
        },
        || {
            let mut t = DefaultWvTester::default();

            let (reqs, mut childmng, child_sub, mut res) = setup_resmng();

            let cid = childmng.next_id();
            let mut childs = wv_assert_ok!(child_sub.create_childs(
                &mut childmng,
                &mut res,
                &mut TestStarter {}
            ));
            wv_assert_eq!(t, childs.len(), 1);

            wv_assert_ok!(Subsystem::start_async(
                &mut childmng,
                &mut childs,
                &reqs,
                &mut res,
                &mut TestStarter {}
            ));
            wv_assert_eq!(t, childmng.children(), 1);

            let child = wv_assert_some!(childmng.child_by_id_mut(cid));

            services(&mut t, child, &mut res);
            memories(&mut t, child, &mut res);
            tiles(&mut t, child, &mut res);

            let sel = child.activity_sel();
            childmng.kill_child_async(&reqs, &mut res, sel, Code::Success);

            wv_assert_eq!(t, childmng.children(), 0);

            Ok(())
        },
    );
}

fn services(t: &mut dyn WvTester, child: &mut dyn Child, res: &mut Resources) {
    wv_assert_err!(
        t,
        child.reg_service(res, 123, 124, "other".to_string(), 16),
        Code::InvArgs
    );
    wv_assert_ok!(child.reg_service(res, 123, 124, "test".to_string(), 16));
    wv_assert_eq!(t, child.res().services().len(), 1);

    wv_assert_err!(t, child.unreg_service(res, 124), Code::InvArgs);
    wv_assert_ok!(child.unreg_service(res, 123));
    wv_assert_eq!(t, child.res().services().len(), 0);
}

fn memories(t: &mut dyn WvTester, child: &mut dyn Child, _res: &mut Resources) {
    const QUOTA: GlobOff = 32 * 1024 * 1024;
    wv_assert_eq!(t, child.res().memories().len(), 0);
    wv_assert_eq!(t, child.mem().quota(), QUOTA);

    wv_assert_err!(t, child.alloc_mem(123, QUOTA * 2, Perm::RW), Code::NoSpace);
    wv_assert_ok!(child.alloc_mem(123, 4 * 1024, Perm::RW));

    wv_assert_eq!(t, child.res().memories().len(), 1);
    wv_assert_eq!(t, child.mem().quota(), QUOTA - (4 * 1024));

    wv_assert_err!(t, child.free_mem(124), Code::InvArgs);
    wv_assert_ok!(child.free_mem(123));

    wv_assert_eq!(t, child.res().memories().len(), 0);
    wv_assert_eq!(t, child.mem().quota(), QUOTA);
}

fn tiles(t: &mut dyn WvTester, child: &mut dyn Child, res: &mut Resources) {
    wv_assert_eq!(t, child.res().tiles().len(), 0);

    let starter = &mut TestStarter {};
    wv_assert_err!(
        t,
        child.alloc_tile(
            res,
            starter,
            123,
            TileDesc::new(TileType::Mem, TileISA::None, 0),
            false,
            false,
        ),
        Code::InvArgs
    );
    wv_assert_ok!(child.alloc_tile(res, starter, 123, Activity::own().tile_desc(), false, false));

    wv_assert_eq!(t, child.res().tiles().len(), 1);

    wv_assert_err!(t, child.free_tile(res, 124), Code::InvArgs);
    wv_assert_ok!(child.free_tile(res, 123));

    wv_assert_eq!(t, child.res().tiles().len(), 0);
}
