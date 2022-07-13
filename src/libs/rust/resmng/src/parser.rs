/*
 * Copyright (C) 2020-2022 Nils Asmussen, Barkhausen Institut
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

use m3::col::{String, ToString, Vec};
use m3::errors::{Code, Error};
use m3::format;
use m3::goff;
use m3::kif;
use m3::rc::Rc;
use m3::tcu::Label;
use m3::util::parse;

use crate::config::{self, MemBandwidth};

struct ConfigParser {
    chars: Vec<char>,
    pos: usize,
}

impl ConfigParser {
    fn new(xml: &str) -> Self {
        ConfigParser {
            chars: xml.chars().collect(),
            pos: 0,
        }
    }

    fn get(&mut self) -> Result<char, Error> {
        if self.pos < self.chars.len() {
            let idx = self.pos;
            self.pos += 1;
            Ok(self.chars[idx])
        }
        else {
            Err(Error::new(Code::InvArgs))
        }
    }

    fn put(&mut self) -> Option<char> {
        if self.pos > 0 {
            self.pos -= 1;
            Some(self.chars[self.pos])
        }
        else {
            None
        }
    }

    fn get_no_ws(&mut self) -> Result<char, Error> {
        loop {
            let c = self.get()?;
            if c.is_whitespace() {
                continue;
            }
            break Ok(c);
        }
    }

    fn consume(&mut self, c: char) -> Result<(), Error> {
        let nc = self.get_no_ws()?;
        if nc != c {
            Err(Error::new(Code::InvArgs))
        }
        else {
            Ok(())
        }
    }

    fn parse_ident(&mut self, delim: char) -> Result<String, Error> {
        let mut name_buf = String::new();
        let first = self.get_no_ws()?;
        name_buf.push(first);

        while let Ok(c) = self.get() {
            if c == delim || c.is_whitespace() {
                break;
            }

            name_buf.push(c);
        }
        Ok(name_buf)
    }

    fn parse_arg(&mut self) -> Result<Option<(String, String)>, Error> {
        let first = self.get_no_ws()?;
        self.put();
        if first == '>' || first == '/' {
            return Ok(None);
        }

        let name = self.parse_ident('=')?;
        self.consume('"')?;

        let mut val_buf = String::new();
        while let Ok(c) = self.get() {
            if c == '"' {
                break;
            }

            val_buf.push(c);
        }
        Ok(Some((name, val_buf)))
    }

    fn parse_tag_name(&mut self) -> Result<Option<String>, Error> {
        self.consume('<')?;

        let mut name_buf = String::new();
        let first = self.get_no_ws()?;

        if first == '/' {
            while let Some(n) = self.put() {
                if n == '<' {
                    return Ok(None);
                }
            }
        }
        name_buf.push(first);

        while let Ok(c) = self.get() {
            if c.is_whitespace() {
                break;
            }
            if c == '>' || c == '/' {
                self.put();
                break;
            }

            name_buf.push(c);
        }

        Ok(Some(name_buf))
    }
}

pub(crate) fn parse(xml: &str) -> Result<config::AppConfig, Error> {
    let mut p = ConfigParser::new(xml);

    match p.parse_tag_name()? {
        Some(tag) if tag == "app" => parse_app(&mut p, 0),
        _ => Err(Error::new(Code::InvArgs)),
    }
}

fn parse_app(p: &mut ConfigParser, start: usize) -> Result<config::AppConfig, Error> {
    let mut app = config::AppConfig::default();

    loop {
        match p.parse_arg()? {
            None => break,
            Some((n, v)) => match n.as_ref() {
                "args" => {
                    for (i, a) in v.split_whitespace().enumerate() {
                        if i == 0 {
                            app.name = a.to_string();
                        }
                        app.args.push(a.to_string());
                    }
                },
                "usermem" => app.user_mem = Some(parse::size(&v)?),
                "kernmem" => app.kern_mem = Some(parse::size(&v)?),
                "time" => app.time = Some(parse::time(&v)?),
                "pagetables" => app.pts = Some(parse::int(&v)? as usize),
                "eps" => app.eps = Some(parse::int(&v)? as u32),
                "mem-bw" => app.mem_bw = Some(parse_mem_bw(&v)?),
                "daemon" => app.daemon = parse::bool(&v)?,
                "getinfo" => app.getinfo = parse::bool(&v)?,
                _ => return Err(Error::new(Code::InvArgs)),
            },
        }
    }

    let nc = p.get_no_ws()?;
    if nc == '/' {
        p.consume('>')?;
        Ok(app)
    }
    else if nc == '>' {
        // put all apps that belong to the same domain as `app` into a pseudo domain
        let mut pseudo_dom = config::Domain {
            pseudo: true,
            ..Default::default()
        };

        let mut app_start = p.pos;
        while let Some(tag) = p.parse_tag_name()? {
            match tag.as_ref() {
                "app" => pseudo_dom.apps.push(Rc::new(parse_app(p, app_start)?)),
                "dom" => app.domains.push(parse_domain(p)?),
                "mount" => app.mounts.push(parse_mount(p)?),
                "sess" => app.sessions.push(parse_session(p)?),
                "sesscrt" => app.sesscrt.push(parse_sesscrt(p)?),
                "serv" => app.services.push(parse_service(p)?),
                "physmem" => app.phys_mems.push(parse_physmem(p)?),
                "tiles" => app.tiles.push(parse_tile(p)?),
                "rgate" => app.rgates.push(parse_rgate(p)?),
                "sgate" => app.sgates.push(parse_sgate(p)?),
                "sem" => app.sems.push(parse_sem(p)?),
                "serial" => app.serial = Some(config::SerialDesc::default()),
                _ => return Err(Error::new(Code::InvArgs)),
            }

            if tag != "dom" && tag != "app" {
                p.consume('/')?;
                p.consume('>')?;
            }
            app_start = p.pos;
        }
        parse_close_tag(p, "app")?;

        if !pseudo_dom.apps.is_empty() {
            app.domains.insert(0, pseudo_dom);
        }

        app.cfg_range = (start, p.pos);
        // don't collect session creators for root
        if start != 0 {
            let mut crts = Vec::new();
            collect_sess_crts(&app, &mut crts);

            for c in crts {
                let duplicate = app.sesscrt.iter().any(|sc| sc.serv_name() == c.serv_name());
                if !duplicate && !hosts_service(&app, c.serv_name()) {
                    app.sesscrt.push(c);
                }
            }
        }

        Ok(app)
    }
    else {
        Err(Error::new(Code::InvArgs))
    }
}

fn hosts_service(app: &config::AppConfig, name: &str) -> bool {
    for d in app.domains() {
        for a in d.apps() {
            if hosts_service(a, name) || a.services().iter().any(|s| s.name().global() == name) {
                return true;
            }
        }
    }
    false
}

fn collect_sess_crts(app: &config::AppConfig, crts: &mut Vec<config::SessCrtDesc>) {
    for d in app.domains() {
        for a in d.apps() {
            for s in a.sessions() {
                if s.is_dep() {
                    crts.push(config::SessCrtDesc::new(s.name().global().clone(), None));
                }
            }
            collect_sess_crts(a, crts);
        }
    }
}

fn parse_dual_name(dual: &mut config::DualName, n: String, v: String) -> Result<(), Error> {
    match n.as_ref() {
        "name" => {
            dual.local = v.clone();
            dual.global = v
        },
        "lname" => dual.local = v,
        "gname" => dual.global = v,
        _ => return Err(Error::new(Code::InvArgs)),
    }
    Ok(())
}

fn parse_domain(p: &mut ConfigParser) -> Result<config::Domain, Error> {
    let mut dom = config::Domain::default();

    loop {
        match p.parse_arg()? {
            None => break,
            Some((n, v)) => match n.as_ref() {
                "tile" => dom.tile = config::TileType(v),
                _ => return Err(Error::new(Code::InvArgs)),
            },
        }
    }

    if dom.tile.0.is_empty() {
        dom.tile = config::TileType("core".to_string());
    }

    p.consume('>')?;

    let mut app_start = p.pos;
    while let Some(tag) = p.parse_tag_name()? {
        if tag != "app" {
            return Err(Error::new(Code::InvArgs));
        }

        dom.apps.push(Rc::new(parse_app(p, app_start)?));
        app_start = p.pos;
    }

    parse_close_tag(p, "dom")?;
    Ok(dom)
}

fn parse_mem_bw(bw: &str) -> Result<MemBandwidth, Error> {
    let rate = parse::size(bw)? as u32;
    Ok(MemBandwidth::new(rate))
}

fn parse_mount(p: &mut ConfigParser) -> Result<config::MountDesc, Error> {
    let mut fs = String::new();
    let mut path = String::new();
    loop {
        match p.parse_arg()? {
            None => break,
            Some((n, v)) => match n.as_ref() {
                "fs" => fs = v.clone(),
                "path" => {
                    if v.ends_with('/') {
                        path = v.clone();
                    }
                    else {
                        path = format!("{}/", v);
                    }
                },
                _ => return Err(Error::new(Code::InvArgs)),
            },
        }
    }
    Ok(config::MountDesc::new(fs, path))
}

fn parse_physmem(p: &mut ConfigParser) -> Result<config::PhysMemDesc, Error> {
    let mut phys = 0;
    let mut size = 0;
    let mut perm = kif::Perm::RWX;
    loop {
        match p.parse_arg()? {
            None => break,
            Some((n, v)) => match n.as_ref() {
                "addr" => phys = parse::addr(&v)?,
                "size" => size = parse::size(&v)? as goff,
                "perm" => perm = parse::perm(&v)?,
                _ => return Err(Error::new(Code::InvArgs)),
            },
        }
    }
    Ok(config::PhysMemDesc::new(phys, size, perm))
}

fn parse_service(p: &mut ConfigParser) -> Result<config::ServiceDesc, Error> {
    let mut name = config::DualName::default();
    loop {
        match p.parse_arg()? {
            None => break,
            Some((n, v)) => parse_dual_name(&mut name, n, v)?,
        }
    }
    Ok(config::ServiceDesc::new(name))
}

fn parse_sesscrt(p: &mut ConfigParser) -> Result<config::SessCrtDesc, Error> {
    let mut name = String::new();
    let mut count = None;
    loop {
        match p.parse_arg()? {
            None => break,
            Some((n, v)) => match n.as_ref() {
                "name" => name = v,
                "count" => count = Some(parse::int(&v)? as u32),
                _ => return Err(Error::new(Code::InvArgs)),
            },
        }
    }
    Ok(config::SessCrtDesc::new(name, count))
}

fn parse_session(p: &mut ConfigParser) -> Result<config::SessionDesc, Error> {
    let mut name = config::DualName::default();
    let mut arg = String::new();
    let mut dep = true;
    loop {
        match p.parse_arg()? {
            None => break,
            Some((n, v)) => match n.as_ref() {
                "name" | "lname" | "gname" => parse_dual_name(&mut name, n, v)?,
                "args" => arg = v,
                "dep" => dep = parse::bool(&v)?,
                _ => return Err(Error::new(Code::InvArgs)),
            },
        }
    }
    Ok(config::SessionDesc::new(name, arg, dep))
}

fn parse_tile(p: &mut ConfigParser) -> Result<config::TileDesc, Error> {
    let mut ty = String::new();
    let mut count = 1;
    let mut optional = false;
    loop {
        match p.parse_arg()? {
            None => break,
            Some((n, v)) => match n.as_ref() {
                "type" => ty = v,
                "count" => count = parse::int(&v)? as u32,
                "optional" => optional = parse::bool(&v)?,
                _ => return Err(Error::new(Code::InvArgs)),
            },
        }
    }
    Ok(config::TileDesc::new(ty, count, optional))
}

fn parse_rgate(p: &mut ConfigParser) -> Result<config::RGateDesc, Error> {
    let mut name = config::DualName::default();
    let mut msg_size = 64;
    let mut slots = 1;
    loop {
        match p.parse_arg()? {
            None => break,
            Some((n, v)) => match n.as_ref() {
                "name" | "lname" | "gname" => parse_dual_name(&mut name, n, v)?,
                "msgsize" => msg_size = parse::size(&v)?,
                "slots" => slots = parse::int(&v)? as usize,
                _ => return Err(Error::new(Code::InvArgs)),
            },
        }
    }
    Ok(config::RGateDesc::new(name, msg_size, slots))
}

fn parse_sgate(p: &mut ConfigParser) -> Result<config::SGateDesc, Error> {
    let mut name = config::DualName::default();
    let mut credits = 1;
    let mut label = 0;
    loop {
        match p.parse_arg()? {
            None => break,
            Some((n, v)) => match n.as_ref() {
                "name" | "lname" | "gname" => parse_dual_name(&mut name, n, v)?,
                "credits" => credits = parse::int(&v)? as u32,
                "label" => label = parse::int(&v)? as Label,
                _ => return Err(Error::new(Code::InvArgs)),
            },
        }
    }
    Ok(config::SGateDesc::new(name, credits, label))
}

fn parse_sem(p: &mut ConfigParser) -> Result<config::SemDesc, Error> {
    let mut name = config::DualName::default();
    loop {
        match p.parse_arg()? {
            None => break,
            Some((n, v)) => parse_dual_name(&mut name, n, v)?,
        }
    }
    Ok(config::SemDesc::new(name))
}

fn parse_close_tag(p: &mut ConfigParser, name: &str) -> Result<(), Error> {
    p.consume('<')?;
    p.consume('/')?;

    let tname = p.parse_ident('>')?;
    if tname != name {
        Err(Error::new(Code::InvArgs))
    }
    else {
        Ok(())
    }
}
