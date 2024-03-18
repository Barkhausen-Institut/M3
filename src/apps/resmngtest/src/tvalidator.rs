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

use m3::errors::Code;
use m3::kif::{boot, TileAttr, TileDesc, TileISA, TileType};
use m3::mem::GlobAddr;
use m3::rc::Rc;
use m3::tcu::TileId;
use m3::tiles::Tile;

use m3::test::WvTester;
use m3::{wv_assert_err, wv_assert_ok, wv_run_test};

use resmng::config::{validator, AppConfig};
use resmng::resources::Resources;

pub fn run(t: &mut dyn WvTester) {
    wv_run_test!(t, services);
    wv_run_test!(t, gates);
    wv_run_test!(t, tiles);
    wv_run_test!(t, mods);
}

fn services(t: &mut dyn WvTester) {
    let res = Resources::default();

    {
        let cfg_str = "<app args=\"ourself\">
            <app args=\"foo\">
                <serv name=\"s1\"/>
                <serv name=\"s1\"/>
            </app>
        </app>";
        let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
        wv_assert_err!(t, validator::validate(&cfg, &res), Code::Exists);
    }

    {
        let cfg_str = "<app args=\"ourself\">
            <app args=\"foo\">
                <serv name=\"s1\"/>
            </app>
            <app args=\"bar\">
                <serv gname=\"s1\" lname=\"something\"/>
            </app>
        </app>";
        let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
        wv_assert_err!(t, validator::validate(&cfg, &res), Code::Exists);
    }

    {
        let cfg_str = "<app args=\"ourself\">
            <app args=\"foo\">
                <serv name=\"s1\"/>
                <sess name=\"s2\"/>
            </app>
        </app>";
        let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
        wv_assert_err!(t, validator::validate(&cfg, &res), Code::NotFound);
    }

    {
        let cfg_str = "<app args=\"ourself\">
            <app args=\"foo\">
                <serv name=\"s1\"/>
                <sess lname=\"s1\" gname=\"s2\"/>
            </app>
        </app>";
        let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
        wv_assert_err!(t, validator::validate(&cfg, &res), Code::NotFound);
    }

    {
        let cfg_str = "<app args=\"ourself\">
            <app args=\"foo\">
                <serv name=\"s1\"/>
                <serv name=\"s2\"/>
                <sess lname=\"s1\" gname=\"s2\"/>
                <sess name=\"s1\"/>
            </app>
        </app>";
        let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
        wv_assert_ok!(validator::validate(&cfg, &res));
    }
}

fn gates(t: &mut dyn WvTester) {
    let res = Resources::default();

    {
        let cfg_str = "<app args=\"ourself\">
            <app args=\"foo\">
                <rgate name=\"g\"/>
                <sgate name=\"s\"/>
            </app>
        </app>";
        let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
        wv_assert_err!(t, validator::validate(&cfg, &res), Code::NotFound);
    }

    {
        let cfg_str = "<app args=\"ourself\">
            <app args=\"foo\">
                <rgate name=\"g\"/>
            </app>
            <app args=\"bar\">
                <sgate lname=\"g\" gname=\"s\"/>
            </app>
        </app>";
        let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
        wv_assert_err!(t, validator::validate(&cfg, &res), Code::NotFound);
    }

    {
        let cfg_str = "<app args=\"ourself\">
            <app args=\"foo\">
                <rgate name=\"g1\"/>
                <rgate name=\"g1\"/>
            </app>
        </app>";
        let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
        wv_assert_err!(t, validator::validate(&cfg, &res), Code::Exists);
    }

    {
        let cfg_str = "<app args=\"ourself\">
            <app args=\"foo\">
                <rgate name=\"g1\" slots=\"2\"/>
                <sgate name=\"g1\"/>
                <sgate name=\"g1\"/>
                <sgate name=\"g1\"/>
            </app>
        </app>";
        let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
        wv_assert_err!(t, validator::validate(&cfg, &res), Code::NoSpace);
    }

    {
        let cfg_str = "<app args=\"ourself\">
            <app args=\"foo\">
                <rgate name=\"g1\" slots=\"2\"/>
                <sgate name=\"g1\"/>
                <sgate name=\"g1\"/>
            </app>
        </app>";
        let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
        wv_assert_ok!(validator::validate(&cfg, &res));
    }
}

fn tiles(t: &mut dyn WvTester) {
    let mut res = Resources::default();
    res.tiles_mut().add(Rc::new(Tile::new_bind_with(
        TileId::new(0, 1),
        TileDesc::new(TileType::Comp, TileISA::RISCV64, 0),
        64,
    )));
    res.tiles_mut().add(Rc::new(Tile::new_bind_with(
        TileId::new(0, 2),
        TileDesc::new_with_attr(TileType::Comp, TileISA::AccelIndir, 0, TileAttr::IMEM),
        65,
    )));

    {
        let cfg_str = "<app args=\"ourself\">
            <app args=\"foo\">
                <tiles type=\"core\" count=\"2\"/>
            </app>
        </app>";
        let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
        wv_assert_err!(t, validator::validate(&cfg, &res), Code::NotFound);
    }

    {
        let cfg_str = "<app args=\"ourself\">
            <app args=\"foo\">
                <tiles type=\"copy\" count=\"1\"/>
            </app>
        </app>";
        let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
        wv_assert_err!(t, validator::validate(&cfg, &res), Code::NotFound);
    }

    {
        let cfg_str = "<app args=\"ourself\">
            <app args=\"foo\">
                <tiles type=\"perf|core\" count=\"1\"/>
                <tiles type=\"indir\" count=\"1\"/>
            </app>
        </app>";
        let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
        wv_assert_ok!(validator::validate(&cfg, &res));
    }
}

fn mods(t: &mut dyn WvTester) {
    let mut res = Resources::default();
    res.mods_mut()
        .add(0, &boot::Mod::new(GlobAddr::new(0x1000), 0x123, "foo"));
    res.mods_mut()
        .add(1, &boot::Mod::new(GlobAddr::new(0x2000), 0x456, "bar"));

    {
        let cfg_str = "<app args=\"ourself\">
            <app args=\"foo\">
                <mod name=\"nope\"/>
            </app>
        </app>";
        let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
        wv_assert_err!(t, validator::validate(&cfg, &res), Code::NotFound);
    }

    {
        let cfg_str = "<app args=\"ourself\">
            <app args=\"foo\">
                <mod name=\"foo\"/>
                <mod lname=\"test\" gname=\"bar\"/>
            </app>
        </app>";
        let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
        wv_assert_ok!(validator::validate(&cfg, &res));
    }
}
