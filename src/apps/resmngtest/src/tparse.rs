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
use m3::kif::Perm;
use m3::test::WvTester;
use m3::time::TimeDuration;
use m3::{wv_assert_eq, wv_assert_err, wv_assert_ok, wv_run_test};

use resmng::config::{
    AppConfig, DualName, ModDesc, MountDesc, RGateDesc, SGateDesc, SemDesc, ServiceDesc,
    SessCrtDesc, SessionDesc, TileDesc, TileType,
};

pub fn run(t: &mut dyn WvTester) {
    wv_run_test!(t, errors);
    wv_run_test!(t, app_short);
    wv_run_test!(t, app_long);
    wv_run_test!(t, app_args);
    wv_run_test!(t, app_mounts);
    wv_run_test!(t, app_mods);
    wv_run_test!(t, app_services);
    wv_run_test!(t, app_sesscrts);
    wv_run_test!(t, app_sessions);
    wv_run_test!(t, app_tiles);
    wv_run_test!(t, app_rgates);
    wv_run_test!(t, app_sgates);
    wv_run_test!(t, app_sems);
    wv_run_test!(t, app_serial);
    wv_run_test!(t, app_domains);
}

fn errors(t: &mut dyn WvTester) {
    wv_assert_err!(t, AppConfig::parse(""), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse("<"), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse(">"), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse("\""), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse("/>"), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse("<>"), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse("app/"), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse("<foo"), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse("<app"), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse("<app>"), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse("app/>"), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse("</app>"), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse("<app><app>"), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse("<app></app"), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse("<app></foo>"), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse("<app></app2>"), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse("<app args=test/>"), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse("<app a=/>"), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse("<app args=\"/>"), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse("<app args=\"\">"), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse("<app/>"), Code::InvArgs);
    wv_assert_err!(t, AppConfig::parse("<app args=\"\"/>"), Code::InvArgs);
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"/><app>"),
        Code::InvArgs
    );
}

fn app_short(t: &mut dyn WvTester) {
    let cfg_str = "<app args=\"foo\"/>";
    let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
    wv_assert_eq!(t, cfg.name(), "foo");
    wv_assert_eq!(t, cfg.args(), &["foo"]);
    wv_assert_eq!(t, cfg.cfg_range(), (0, cfg_str.len()));
}

fn app_long(t: &mut dyn WvTester) {
    let cfg_str = "<app args=\"foo\"></app>";
    let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
    wv_assert_eq!(t, cfg.name(), "foo");
    wv_assert_eq!(t, cfg.args(), &["foo"]);
    wv_assert_eq!(t, cfg.cfg_range(), (0, cfg_str.len()));
}

fn app_args(t: &mut dyn WvTester) {
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\" daemon=\"bar\"/>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\" usermem=\"4x\"/>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\" kernmem=\"\"/>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\" time=\"1k\"/>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\" pagetables=\"foo\"/>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\" eps=\"bar\"/>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\" getinfo=\"a\"/>"),
        Code::InvArgs
    );

    let cfg_str = "<app args=\"foo test 22\" daemon=\"1\"
                        usermem=\"4M\" kernmem=\"32M\"
                        time=\"4ms\" pagetables=\"18\"
                        eps=\"64\" getinfo=\"1\"/>";
    let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
    wv_assert_eq!(t, cfg.name(), "foo");
    wv_assert_eq!(t, cfg.args(), &["foo", "test", "22"]);
    wv_assert_eq!(t, cfg.cfg_range(), (0, cfg_str.len()));
    wv_assert_eq!(t, cfg.daemon(), true);
    wv_assert_eq!(t, cfg.user_mem(), Some(4 * 1024 * 1024));
    wv_assert_eq!(t, cfg.kernel_mem(), Some(32 * 1024 * 1024));
    wv_assert_eq!(t, cfg.time(), Some(TimeDuration::from_millis(4)));
    wv_assert_eq!(t, cfg.page_tables(), Some(18));
    wv_assert_eq!(t, cfg.eps(), Some(64));
    wv_assert_eq!(t, cfg.can_get_info(), true);
}

fn app_mounts(t: &mut dyn WvTester) {
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><mount /></app>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><mount fs=\"\" /></app>"),
        Code::InvArgs
    );

    {
        let cfg = wv_assert_ok!(AppConfig::parse(
            "<app  \t\n args = \"foo\"   > < mount  fs=\"myfs\" path=\"\"   / > < / app >"
        ));
        wv_assert_eq!(t, cfg.mounts(), &[MountDesc::new(
            "myfs".to_string(),
            "/".to_string()
        )]);
    }

    {
        let cfg = wv_assert_ok!(AppConfig::parse(
            "<app args=\"foo\"><mount fs=\"myfs\" path=\"/bar\"/></app>"
        ));
        wv_assert_eq!(t, cfg.mounts(), &[MountDesc::new(
            "myfs".to_string(),
            "/bar/".to_string()
        )]);
    }
}

fn app_mods(t: &mut dyn WvTester) {
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><mod/></app>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><mod foo=\"bar\"/></app>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><mod name=\"\"/></app>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><mod gname=\"global\"/></app>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><mod lname=\"local\"/></app>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><mod name=\"test\" perm=\"y\"/></app>"),
        Code::InvArgs
    );

    let cfg_str = "<app args=\"foo\">
        <mod name=\"mod1\" perm=\"rw\"/>
        <mod name=\"mod2\" perm=\"rwx\"/>
        <mod name=\"mod3\" perm=\"\"/>
        <mod lname=\"mod4\" gname=\"gmod4\" perm=\"rx\"/>
    </app>";
    let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
    wv_assert_eq!(t, cfg.mods(), &[
        ModDesc::new(DualName::new_simple("mod1".to_string()), Perm::RW),
        ModDesc::new(DualName::new_simple("mod2".to_string()), Perm::RWX),
        ModDesc::new(DualName::new_simple("mod3".to_string()), Perm::empty()),
        ModDesc::new(
            DualName::new("mod4".to_string(), "gmod4".to_string()),
            Perm::R | Perm::X
        )
    ]);
}

fn app_services(t: &mut dyn WvTester) {
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><serv/></app>"),
        Code::InvArgs
    );

    let cfg_str = "<app args=\"foo\">
        <serv name=\"service\"/>
        <serv lname=\"lserv\" gname=\"gserv\"/>
    </app>";
    let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
    wv_assert_eq!(t, cfg.services(), &[
        ServiceDesc::new(DualName::new_simple("service".to_string())),
        ServiceDesc::new(DualName::new("lserv".to_string(), "gserv".to_string()))
    ]);
}

fn app_sesscrts(t: &mut dyn WvTester) {
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><sesscrt/></app>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><sesscrt name=\"test\" count=\"bar\"/></app>"),
        Code::InvArgs
    );

    let cfg_str = "<app args=\"foo\">
        <sesscrt name=\"service\"/>
        <sesscrt name=\"service2\" count=\"4\"/>
    </app>";
    let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
    wv_assert_eq!(t, cfg.sess_creators(), &[
        SessCrtDesc::new("service".to_string(), None),
        SessCrtDesc::new("service2".to_string(), Some(4))
    ]);
}

fn app_sessions(t: &mut dyn WvTester) {
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><sess/></app>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><sess gname=\"g\"/></app>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><sess name=\"test\" dep=\"invalid\"/></app>"),
        Code::InvArgs
    );

    let cfg_str = "<app args=\"foo\">
        <sess name=\"myserv\" args=\"test 1 2 3\"/>
        <sess lname=\"lserv\" gname=\"gserv\" dep=\"false\"/>
    </app>";
    let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
    wv_assert_eq!(t, cfg.sessions(), &[
        SessionDesc::new(
            DualName::new_simple("myserv".to_string()),
            "test 1 2 3".to_string(),
            true,
        ),
        SessionDesc::new(
            DualName::new("lserv".to_string(), "gserv".to_string()),
            "".to_string(),
            false
        )
    ]);
}

fn app_tiles(t: &mut dyn WvTester) {
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><tiles/></app>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><tiles type=\"core\" count=\"a\"/></app>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><tiles type=\"core\" optional=\"a\"/></app>"),
        Code::InvArgs
    );

    let cfg_str = "<app args=\"foo\">
        <tiles type=\"core\"/>
        <tiles type=\"core|perf\" count=\"4\"/>
        <tiles type=\"net\" count=\"1\" optional=\"true\"/>
        <tiles type=\"boom\" mux=\"mymux\"/>
        <tiles type=\"rocket\" mux=\"-\"/>
    </app>";
    let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
    wv_assert_eq!(t, cfg.tiles(), &[
        TileDesc::new("core".to_string(), 1, Some("tilemux".to_string()), false),
        TileDesc::new(
            "core|perf".to_string(),
            4,
            Some("tilemux".to_string()),
            false
        ),
        TileDesc::new("net".to_string(), 1, Some("tilemux".to_string()), true),
        TileDesc::new("boom".to_string(), 1, Some("mymux".to_string()), false),
        TileDesc::new("rocket".to_string(), 1, None, false),
    ]);
}

fn app_rgates(t: &mut dyn WvTester) {
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><rgate/></app>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><rgate msgsize=\"a\"/></app>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><rgate slots=\"a\"/></app>"),
        Code::InvArgs
    );

    let cfg_str = "<app args=\"foo\">
        <rgate name=\"rg\"/>
        <rgate gname=\"g\" lname=\"l\" msgsize=\"64\"/>
        <rgate name=\"test\" msgsize=\"128\" slots=\"4\"/>
    </app>";
    let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
    wv_assert_eq!(t, cfg.rgates(), &[
        RGateDesc::new(DualName::new_simple("rg".to_string()), 64, 1),
        RGateDesc::new(DualName::new("l".to_string(), "g".to_string()), 64, 1),
        RGateDesc::new(DualName::new_simple("test".to_string()), 128, 4),
    ]);
}

fn app_sgates(t: &mut dyn WvTester) {
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><sgate/></app>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><sgate credits=\"a\"/></app>"),
        Code::InvArgs
    );
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><sgate label=\"a\"/></app>"),
        Code::InvArgs
    );

    let cfg_str = "<app args=\"foo\">
        <sgate name=\"sg\"/>
        <sgate gname=\"g\" lname=\"l\" credits=\"2\"/>
        <sgate name=\"test\" credits=\"4\" label=\"4000\"/>
    </app>";
    let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
    wv_assert_eq!(t, cfg.sgates(), &[
        SGateDesc::new(DualName::new_simple("sg".to_string()), 1, 0),
        SGateDesc::new(DualName::new("l".to_string(), "g".to_string()), 2, 0),
        SGateDesc::new(DualName::new_simple("test".to_string()), 4, 4000),
    ]);
}

fn app_sems(t: &mut dyn WvTester) {
    wv_assert_err!(
        t,
        AppConfig::parse("<app args=\"foo\"><sem/></app>"),
        Code::InvArgs
    );

    let cfg_str = "<app args=\"foo\">
        <sem name=\"a\"/>
        <sem lname=\"l\" gname=\"g\"/>
    </app>";
    let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
    wv_assert_eq!(t, cfg.semaphores(), &[
        SemDesc::new(DualName::new_simple("a".to_string())),
        SemDesc::new(DualName::new("l".to_string(), "g".to_string()))
    ]);
}

fn app_serial(t: &mut dyn WvTester) {
    let cfg_str = "<app args=\"foo\">
        <serial/>
    </app>";
    let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));
    wv_assert_eq!(t, cfg.alloc_serial(), true);
}

fn app_domains(t: &mut dyn WvTester) {
    let cfg_str = "<app args=\"foo\">
            <app args=\"bar\"/>
            <dom tile=\"perf\"><app args=\"zap\"/></dom>
        </app>";
    let cfg = wv_assert_ok!(AppConfig::parse(cfg_str));

    // compare the relevant properties manually here, because we cannot compare AppConfig's as we
    // don't know/can't set the cfg_range.
    wv_assert_eq!(t, cfg.domains().len(), 2);
    wv_assert_eq!(t, cfg.domains()[0].pseudo(), true);
    wv_assert_eq!(t, *cfg.domains()[0].tile(), TileType("core".to_string()));
    wv_assert_eq!(t, cfg.domains()[0].apps()[0].name(), "bar");
    wv_assert_eq!(t, cfg.domains()[1].pseudo(), false);
    wv_assert_eq!(t, *cfg.domains()[1].tile(), TileType("perf".to_string()));
    wv_assert_eq!(t, cfg.domains()[1].apps()[0].name(), "zap");
}
