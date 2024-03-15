/*
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

pub mod parser;
pub mod validator;

use core::fmt;
use m3::cell::Cell;
use m3::cfg;
use m3::col::{String, Vec};
use m3::errors::{Code, Error};
use m3::kif;
use m3::rc::Rc;
use m3::tcu::Label;
use m3::time::TimeDuration;

#[derive(Default, Eq, PartialEq)]
pub struct DualName {
    pub(crate) local: String,
    pub(crate) global: String,
}

impl DualName {
    pub fn new_simple(name: String) -> Self {
        Self {
            local: name.clone(),
            global: name,
        }
    }

    pub fn new(local: String, global: String) -> Self {
        Self { local, global }
    }

    pub fn is_empty(&self) -> bool {
        self.local.is_empty() || self.global.is_empty()
    }

    pub fn local(&self) -> &String {
        &self.local
    }

    pub fn global(&self) -> &String {
        &self.global
    }
}

impl fmt::Debug for DualName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "lname='{}', gname='{}'", self.local, self.global)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ModDesc {
    name: DualName,
    perm: kif::Perm,
}

impl ModDesc {
    pub fn new(name: DualName, perm: kif::Perm) -> Self {
        Self { name, perm }
    }

    pub fn name(&self) -> &DualName {
        &self.name
    }

    pub fn perm(&self) -> kif::Perm {
        self.perm
    }
}

#[derive(Default, Debug, Eq, PartialEq)]
pub struct MountDesc {
    fs: String,
    path: String,
}

impl MountDesc {
    pub fn new(fs: String, path: String) -> Self {
        Self { fs, path }
    }

    pub fn fs(&self) -> &String {
        &self.fs
    }

    pub fn path(&self) -> &String {
        &self.path
    }
}

#[derive(Default, Debug, Eq, PartialEq)]
pub struct ServiceDesc {
    name: DualName,
    used: Cell<bool>,
}

impl ServiceDesc {
    pub fn new(name: DualName) -> Self {
        Self {
            name,
            used: Cell::new(false),
        }
    }

    pub fn name(&self) -> &DualName {
        &self.name
    }

    pub fn is_used(&self) -> bool {
        self.used.get()
    }

    pub fn mark_used(&self) {
        self.used.replace(true);
    }
}

#[derive(Default, Debug, Eq, PartialEq)]
pub struct SessCrtDesc {
    name: String,
    count: Option<u32>,
}

impl SessCrtDesc {
    pub fn new(name: String, count: Option<u32>) -> Self {
        Self { name, count }
    }

    pub fn serv_name(&self) -> &String {
        &self.name
    }

    pub fn sess_count(&self) -> Option<u32> {
        self.count
    }
}

#[derive(Default, Debug, Eq, PartialEq)]
pub struct SessionDesc {
    name: DualName,
    arg: String,
    dep: bool,
    used: Cell<bool>,
}

impl SessionDesc {
    pub fn new(name: DualName, arg: String, dep: bool) -> Self {
        Self {
            name,
            arg,
            dep,
            used: Cell::new(false),
        }
    }

    pub fn is_dep(&self) -> bool {
        self.dep
    }

    pub fn name(&self) -> &DualName {
        &self.name
    }

    pub fn arg(&self) -> &String {
        &self.arg
    }

    pub fn is_used(&self) -> bool {
        self.used.get()
    }

    pub fn mark_used(&self) {
        self.used.replace(true);
    }
}

#[derive(Default, Debug, Eq, PartialEq)]
pub struct RGateDesc {
    name: DualName,
    msg_size: usize,
    slots: usize,
}

impl RGateDesc {
    pub fn new(name: DualName, msg_size: usize, slots: usize) -> Self {
        Self {
            name,
            msg_size,
            slots,
        }
    }

    pub fn name(&self) -> &DualName {
        &self.name
    }

    pub fn msg_size(&self) -> usize {
        self.msg_size
    }

    pub fn slots(&self) -> usize {
        self.slots
    }
}

#[derive(Default, Debug, Eq, PartialEq)]
pub struct SGateDesc {
    name: DualName,
    credits: u32,
    label: Label,
    used: Cell<bool>,
}

impl SGateDesc {
    pub fn new(name: DualName, credits: u32, label: Label) -> Self {
        Self {
            name,
            credits,
            label,
            used: Cell::new(false),
        }
    }

    pub fn name(&self) -> &DualName {
        &self.name
    }

    pub fn credits(&self) -> u32 {
        self.credits
    }

    pub fn label(&self) -> Label {
        self.label
    }

    pub fn is_used(&self) -> bool {
        self.used.get()
    }

    pub fn mark_used(&self) {
        self.used.replace(true);
    }
}

#[derive(Default, Debug, Eq, PartialEq)]
pub struct TileType(pub String);

impl TileType {
    pub fn matches(&self, desc: kif::TileDesc) -> bool {
        for attrs in self.0.split('|') {
            if self.attrs_match(desc, attrs) {
                return true;
            }
        }
        false
    }

    fn attrs_match(&self, desc: kif::TileDesc, attrs: &str) -> bool {
        for attr in attrs.split('+') {
            let matches = match attr {
                "core" => desc.is_programmable(),

                "arm" => desc.isa() == kif::TileISA::ARM,
                "x86" => desc.isa() == kif::TileISA::X86,
                "riscv64" => desc.isa() == kif::TileISA::RISCV64,

                "nic" => desc.attr().contains(kif::TileAttr::NIC),
                "perf" => desc.attr().contains(kif::TileAttr::PERF),
                "effi" => desc.attr().contains(kif::TileAttr::EFFI),
                "kecacc" => desc.attr().contains(kif::TileAttr::KECACC),
                "serial" => desc.attr().contains(kif::TileAttr::SERIAL),
                "imem" => desc.attr().contains(kif::TileAttr::IMEM),

                "indir" => desc.isa() == kif::TileISA::AccelIndir,
                "copy" => desc.isa() == kif::TileISA::AccelCopy,
                "rot13" => desc.isa() == kif::TileISA::AccelRot13,

                "idedev" => desc.isa() == kif::TileISA::IDEDev,
                "nicdev" => desc.isa() == kif::TileISA::NICDev,
                "serdev" => desc.isa() == kif::TileISA::SerialDev,
                _ => false,
            };
            if !matches {
                return false;
            }
        }
        true
    }
}

#[derive(Default, Debug, Eq, PartialEq)]
pub struct TileDesc {
    ty: TileType,
    count: Cell<u32>,
    optional: bool,
}

impl TileDesc {
    pub fn new(ty: String, count: u32, optional: bool) -> Self {
        Self {
            ty: TileType(ty),
            count: Cell::new(count),
            optional,
        }
    }

    pub fn optional(&self) -> bool {
        self.optional
    }

    pub fn tile_type(&self) -> &TileType {
        &self.ty
    }

    pub fn count(&self) -> u32 {
        self.count.get()
    }

    pub fn alloc(&self) {
        assert!(self.count.get() > 0);
        self.count.set(self.count.get() - 1);
    }

    pub fn free(&self) {
        self.count.set(self.count.get() + 1);
    }
}

#[derive(Default, Debug, Eq, PartialEq)]
pub struct SemDesc {
    name: DualName,
}

impl SemDesc {
    pub fn new(name: DualName) -> Self {
        SemDesc { name }
    }

    pub fn name(&self) -> &DualName {
        &self.name
    }
}

#[derive(Default, Debug, Eq, PartialEq)]
pub struct SerialDesc {
    used: Cell<bool>,
}

#[derive(Default, Debug)]
pub struct Domain {
    pub(crate) pseudo: bool,
    pub(crate) tile: TileType,
    pub(crate) mux: Option<String>,
    pub(crate) mux_mem: Option<usize>,
    pub(crate) initrd: Option<String>,
    pub(crate) dtb: Option<String>,
    pub(crate) apps: Vec<Rc<AppConfig>>,
}

impl Domain {
    pub fn new(pseudo: bool, tile: TileType, apps: Vec<Rc<AppConfig>>) -> Self {
        Self {
            pseudo,
            tile,
            mux: None,
            mux_mem: None,
            initrd: None,
            dtb: None,
            apps,
        }
    }

    pub fn pseudo(&self) -> bool {
        self.pseudo
    }

    pub fn apps(&self) -> &Vec<Rc<AppConfig>> {
        &self.apps
    }

    pub fn mux(&self) -> Option<&str> {
        self.mux.as_deref()
    }

    pub fn mux_mem(&self) -> Option<usize> {
        self.mux_mem
    }

    pub fn initrd(&self) -> Option<&str> {
        self.initrd.as_deref()
    }

    pub fn dtb(&self) -> Option<&str> {
        self.dtb.as_deref()
    }

    pub fn tile(&self) -> &TileType {
        &self.tile
    }
}

#[derive(Default)]
pub struct AppConfig {
    pub(crate) name: String,
    pub(crate) args: Vec<String>,
    pub(crate) cfg_range: (usize, usize),
    pub(crate) daemon: bool,
    pub(crate) getinfo: bool,
    pub(crate) eps: Option<usize>,
    pub(crate) user_mem: Option<usize>,
    pub(crate) kern_mem: Option<usize>,
    pub(crate) time: Option<TimeDuration>,
    pub(crate) pts: Option<usize>,
    pub(crate) serial: Option<SerialDesc>,
    pub(crate) domains: Vec<Domain>,
    pub(crate) mounts: Vec<MountDesc>,
    pub(crate) mods: Vec<ModDesc>,
    pub(crate) services: Vec<ServiceDesc>,
    pub(crate) sesscrt: Vec<SessCrtDesc>,
    pub(crate) sessions: Vec<SessionDesc>,
    pub(crate) rgates: Vec<RGateDesc>,
    pub(crate) sgates: Vec<SGateDesc>,
    pub(crate) sems: Vec<SemDesc>,
    pub(crate) tiles: Vec<TileDesc>,
}

impl AppConfig {
    pub fn parse(xml: &str) -> Result<Self, Error> {
        parser::parse(xml)
    }

    pub fn new(args: Vec<String>) -> Self {
        assert!(!args.is_empty());
        Self {
            name: args[0].clone(),
            args,
            ..Default::default()
        }
    }

    pub fn cfg_range(&self) -> (usize, usize) {
        self.cfg_range
    }

    pub fn daemon(&self) -> bool {
        self.daemon
    }

    pub fn can_get_info(&self) -> bool {
        self.getinfo
    }

    pub fn can_get_serial(&self) -> bool {
        self.serial.is_some()
    }

    pub fn eps(&self) -> Option<usize> {
        self.eps
    }

    pub fn user_mem(&self) -> Option<usize> {
        self.user_mem
    }

    pub fn kernel_mem(&self) -> Option<usize> {
        self.kern_mem
    }

    pub fn time(&self) -> Option<TimeDuration> {
        self.time
    }

    pub fn page_tables(&self) -> Option<usize> {
        self.pts
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn args(&self) -> &Vec<String> {
        &self.args
    }

    pub fn domains(&self) -> &Vec<Domain> {
        &self.domains
    }

    pub fn mounts(&self) -> &Vec<MountDesc> {
        &self.mounts
    }

    pub fn mods(&self) -> &Vec<ModDesc> {
        &self.mods
    }

    pub fn services(&self) -> &Vec<ServiceDesc> {
        &self.services
    }

    pub fn sessions(&self) -> &Vec<SessionDesc> {
        &self.sessions
    }

    pub fn tiles(&self) -> &Vec<TileDesc> {
        &self.tiles
    }

    pub fn sess_creators(&self) -> &Vec<SessCrtDesc> {
        &self.sesscrt
    }

    pub fn rgates(&self) -> &Vec<RGateDesc> {
        &self.rgates
    }

    pub fn sgates(&self) -> &Vec<SGateDesc> {
        &self.sgates
    }

    pub fn semaphores(&self) -> &Vec<SemDesc> {
        &self.sems
    }

    pub fn get_mod(&self, lname: &str) -> Option<&ModDesc> {
        self.mods.iter().find(|r| r.name().local() == lname)
    }

    pub fn get_rgate(&self, lname: &str) -> Option<&RGateDesc> {
        self.rgates.iter().find(|r| r.name().local() == lname)
    }

    pub fn get_sgate(&self, lname: &str) -> Option<&SGateDesc> {
        self.sgates.iter().find(|s| s.name().local() == lname)
    }

    pub fn get_sem(&self, lname: &str) -> Option<&SemDesc> {
        self.sems.iter().find(|s| s.name().local() == lname)
    }

    pub fn get_service(&self, lname: &str) -> Option<&ServiceDesc> {
        self.services.iter().find(|s| s.name().local() == lname)
    }

    pub fn unreg_service(&self, gname: &str) {
        let serv = self
            .services
            .iter()
            .find(|s| s.name().global() == gname)
            .unwrap();
        serv.used.replace(false);
    }

    pub fn get_session(&self, lname: &str) -> Option<(usize, &SessionDesc)> {
        self.sessions
            .iter()
            .position(|s| s.name().local() == lname)
            .map(|idx| (idx, &self.sessions[idx]))
    }

    pub fn close_session(&self, idx: usize) {
        self.sessions[idx].used.replace(false);
    }

    pub fn get_tile_idx(&self, desc: kif::TileDesc) -> Result<usize, Error> {
        let idx = self
            .tiles
            .iter()
            .position(|tile| tile.count.get() > 0 && tile.tile_type().matches(desc))
            .ok_or_else(|| Error::new(Code::InvArgs))?;

        if self.tiles[idx].count.get() > 0 {
            Ok(idx)
        }
        else {
            Err(Error::new(Code::NoSpace))
        }
    }

    pub fn alloc_serial(&self) -> bool {
        match &self.serial {
            Some(s) => {
                s.used.set(true);
                true
            },
            None => false,
        }
    }

    pub fn alloc_tile(&self, idx: usize) {
        self.tiles[idx].alloc();
    }

    pub fn free_tile(&self, idx: usize) {
        self.tiles[idx].free();
    }

    pub fn count_apps(&self) -> usize {
        self.domains.iter().fold(0, |total, d| total + d.apps.len())
    }

    fn print_rec(&self, f: &mut fmt::Formatter<'_>, layer: usize) -> Result<(), fmt::Error> {
        write!(f, "{:0w$}", "", w = layer)?;
        for a in &self.args {
            write!(f, "{} ", a)?;
        }
        writeln!(f, "[")?;
        if self.daemon {
            writeln!(f, "{:0w$}Daemon,", "", w = layer + 2)?;
        }
        if let Some(eps) = self.eps {
            writeln!(f, "{:0w$}Endpoints[count={}],", "", eps, w = layer + 2)?;
        }
        if let Some(t) = self.time {
            writeln!(f, "{:0w$}TimeSlice[{:?}],", "", t, w = layer + 2)?;
        }
        if let Some(n) = self.pts {
            writeln!(f, "{:0w$}PageTables[{}],", "", n, w = layer + 2)?;
        }
        if let Some(umem) = self.user_mem {
            writeln!(
                f,
                "{:0w$}UserMem[size={} KiB],",
                "",
                umem / 1024,
                w = layer + 2
            )?;
        }
        if let Some(kmem) = self.kern_mem {
            writeln!(
                f,
                "{:0w$}KernelMem[size={} KiB],",
                "",
                kmem / 1024,
                w = layer + 2
            )?;
        }
        for m in &self.mods {
            writeln!(
                f,
                "{:0w$}Mod[{:?}, perm={:?}],",
                "",
                m.name,
                m.perm(),
                w = layer + 2
            )?;
        }
        for s in &self.sems {
            writeln!(f, "{:0w$}Semaphore[{:?}],", "", s.name, w = layer + 2)?;
        }
        for s in &self.services {
            writeln!(f, "{:0w$}Service[{:?}],", "", s.name, w = layer + 2)?;
        }
        for s in &self.sesscrt {
            writeln!(
                f,
                "{:0w$}SessCreator[service='{}', count={:?}],",
                "",
                s.serv_name(),
                s.sess_count(),
                w = layer + 2
            )?;
        }
        for s in &self.sessions {
            writeln!(
                f,
                "{:0w$}Session[{:?}, arg='{}', dep={}],",
                "",
                s.name,
                s.arg,
                s.dep,
                w = layer + 2
            )?;
        }
        for r in &self.rgates {
            writeln!(
                f,
                "{:0w$}RGate[{:?}, msgsize='{}', slots={}],",
                "",
                r.name,
                r.msg_size,
                r.slots,
                w = layer + 2
            )?;
        }
        for s in &self.sgates {
            writeln!(
                f,
                "{:0w$}SGate[{:?}, credits='{}', label={:#x}],",
                "",
                s.name,
                s.credits,
                s.label,
                w = layer + 2
            )?;
        }
        for m in &self.mounts {
            writeln!(
                f,
                "{:0w$}Mount[fs='{}', path='{}'],",
                "",
                m.fs,
                m.path,
                w = layer + 2
            )?;
        }
        for tile in &self.tiles {
            writeln!(
                f,
                "{:0w$}Tile[type={}, count={}, optional={}],",
                "",
                tile.tile_type().0,
                tile.count.get(),
                tile.optional,
                w = layer + 2
            )?;
        }
        if self.serial.is_some() {
            writeln!(f, "{:0w$}Serial[],", "", w = layer + 2)?;
        }
        if self.can_get_info() {
            writeln!(f, "{:0w$}GetInfo[],", "", w = layer + 2)?;
        }
        for d in &self.domains {
            let mut sub_layer = layer;
            if !d.pseudo {
                writeln!(
                    f,
                    "{:0w$}Domain on {} with mux=({}, {}M, {:?}, {:?}) [",
                    "",
                    d.tile.0,
                    d.mux().unwrap_or("tilemux"),
                    d.mux_mem.unwrap_or(cfg::FIXED_TILEMUX_MEM) / (1024 * 1024),
                    d.initrd(),
                    d.dtb(),
                    w = layer + 2
                )?;
                sub_layer += 2;
            }
            for a in &d.apps {
                a.print_rec(f, sub_layer + 2)?;
            }
            if !d.pseudo {
                writeln!(f, "{:0w$}]", "", w = layer + 2)?;
            }
        }
        writeln!(f, "{:0w$}]", "", w = layer)
    }
}

impl fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "Config [")?;
        self.print_rec(f, 2)?;
        writeln!(f, "]")
    }
}