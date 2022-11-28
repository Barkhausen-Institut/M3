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

use core::fmt;
use m3::cell::Cell;
use m3::col::{BTreeMap, BTreeSet, String, Vec};
use m3::errors::{Code, Error};
use m3::goff;
use m3::kif;
use m3::rc::Rc;
use m3::tcu::Label;

use crate::parser;
use crate::tiles;

#[derive(Default)]
pub struct DualName {
    pub(crate) local: String,
    pub(crate) global: String,
}

impl DualName {
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

pub struct PhysMemDesc {
    // TODO add memory id
    phys: goff,
    size: goff,
    perm: kif::Perm,
}

impl PhysMemDesc {
    pub(crate) fn new(phys: goff, size: goff, perm: kif::Perm) -> Self {
        Self { phys, size, perm }
    }

    pub fn phys(&self) -> goff {
        self.phys
    }

    pub fn size(&self) -> goff {
        self.size
    }

    pub fn perm(&self) -> kif::Perm {
        self.perm
    }
}

#[derive(Default)]
pub struct MountDesc {
    fs: String,
    path: String,
}

impl MountDesc {
    pub(crate) fn new(fs: String, path: String) -> Self {
        Self { fs, path }
    }

    pub fn fs(&self) -> &String {
        &self.fs
    }

    pub fn path(&self) -> &String {
        &self.path
    }
}

#[derive(Default)]
pub struct ServiceDesc {
    name: DualName,
    used: Cell<bool>,
}

impl ServiceDesc {
    pub(crate) fn new(name: DualName) -> Self {
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

#[derive(Default)]
pub struct SessCrtDesc {
    name: String,
    count: Option<u32>,
}

impl SessCrtDesc {
    pub(crate) fn new(name: String, count: Option<u32>) -> Self {
        Self { name, count }
    }

    pub fn serv_name(&self) -> &String {
        &self.name
    }

    pub fn sess_count(&self) -> Option<u32> {
        self.count
    }
}

#[derive(Default)]
pub struct SessionDesc {
    name: DualName,
    arg: String,
    dep: bool,
    used: Cell<bool>,
}

impl SessionDesc {
    pub(crate) fn new(name: DualName, arg: String, dep: bool) -> Self {
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

pub struct RGateDesc {
    name: DualName,
    msg_size: usize,
    slots: usize,
}

impl RGateDesc {
    pub(crate) fn new(name: DualName, msg_size: usize, slots: usize) -> Self {
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

pub struct SGateDesc {
    name: DualName,
    credits: u32,
    label: Label,
    used: Cell<bool>,
}

impl SGateDesc {
    pub(crate) fn new(name: DualName, credits: u32, label: Label) -> Self {
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

#[derive(Default)]
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

                "imem" => desc.tile_type() == kif::TileType::COMP_IMEM,
                "emem" => desc.tile_type() == kif::TileType::COMP_EMEM,
                "vm" => desc.has_virtmem(),

                "arm" => desc.isa() == kif::TileISA::ARM,
                "x86" => desc.isa() == kif::TileISA::X86,
                "riscv" => desc.isa() == kif::TileISA::RISCV,

                "nic" => desc.attr().contains(kif::TileAttr::NIC),
                "boom" => desc.attr().contains(kif::TileAttr::BOOM),
                "rocket" => desc.attr().contains(kif::TileAttr::ROCKET),
                "kecacc" => desc.attr().contains(kif::TileAttr::KECACC),

                "indir" => desc.isa() == kif::TileISA::ACCEL_INDIR,
                "copy" => desc.isa() == kif::TileISA::ACCEL_COPY,
                "rot13" => desc.isa() == kif::TileISA::ACCEL_ROT13,

                "idedev" => desc.isa() == kif::TileISA::IDE_DEV,
                "nicdev" => desc.isa() == kif::TileISA::NIC_DEV,
                _ => false,
            };
            if !matches {
                return false;
            }
        }
        true
    }
}

#[derive(Default)]
pub struct TileDesc {
    ty: TileType,
    count: Cell<u32>,
    optional: bool,
}

impl TileDesc {
    pub(crate) fn new(ty: String, count: u32, optional: bool) -> Self {
        Self {
            ty: TileType(ty),
            count: Cell::new(count),
            optional,
        }
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

pub struct SemDesc {
    name: DualName,
}

impl SemDesc {
    pub(crate) fn new(name: DualName) -> Self {
        SemDesc { name }
    }

    pub fn name(&self) -> &DualName {
        &self.name
    }
}

#[derive(Default)]
pub struct SerialDesc {
    used: Cell<bool>,
}

#[derive(Default)]
pub struct Domain {
    pub(crate) pseudo: bool,
    pub(crate) tile: TileType,
    pub(crate) apps: Vec<Rc<AppConfig>>,
}

impl Domain {
    pub fn apps(&self) -> &Vec<Rc<AppConfig>> {
        &self.apps
    }

    pub fn tile(&self) -> &TileType {
        &self.tile
    }
}

#[derive(Default)]
pub struct AppConfig {
    pub(crate) name: String,
    pub(crate) args: Vec<String>,
    pub(crate) hash: Option<String>,
    pub(crate) cfg_range: (usize, usize),
    pub(crate) daemon: bool,
    pub(crate) getinfo: bool,
    pub(crate) eps: Option<u32>,
    pub(crate) user_mem: Option<usize>,
    pub(crate) kern_mem: Option<usize>,
    pub(crate) time: Option<u64>,
    pub(crate) pts: Option<usize>,
    pub(crate) serial: Option<SerialDesc>,
    pub(crate) domains: Vec<Domain>,
    pub(crate) mounts: Vec<MountDesc>,
    pub(crate) phys_mems: Vec<PhysMemDesc>,
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

    pub fn hash(&self) -> Option<&String> {
        self.hash.as_ref()
    }

    pub fn can_get_info(&self) -> bool {
        self.getinfo
    }

    pub fn eps(&self) -> Option<u32> {
        self.eps
    }

    pub fn user_mem(&self) -> Option<usize> {
        self.user_mem
    }

    pub fn kernel_mem(&self) -> Option<usize> {
        self.kern_mem
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

    pub fn phys_mems(&self) -> &Vec<PhysMemDesc> {
        &self.phys_mems
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

    pub fn get_pe_idx(&self, desc: kif::TileDesc) -> Result<usize, Error> {
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

    pub fn check(&self) {
        self.check_services(&BTreeSet::new());
        self.check_gates();
        self.check_tiles();
    }

    fn count_tiles(tile: &TileDesc) -> u32 {
        let mut count = 0;
        for i in 0..tiles::get().count() {
            if tile.tile_type().matches(tiles::get().get(i).desc()) {
                count += 1;
            }
        }
        count
    }

    fn check_tiles(&self) {
        for d in &self.domains {
            for a in &d.apps {
                a.check_tiles();
            }
        }

        for tile in &self.tiles {
            if !tile.optional {
                let available = Self::count_tiles(tile);
                if available < tile.count.get() {
                    panic!(
                        "AppConfig '{}' needs tile type '{}' {} times, but {} are available",
                        self.name(),
                        tile.tile_type().0,
                        tile.count.get(),
                        available
                    );
                }
            }
        }
    }

    fn check_services(&self, parent_set: &BTreeSet<String>) {
        let mut set = BTreeSet::new();
        for d in &self.domains {
            for a in &d.apps {
                for serv in a.services() {
                    if set.contains(serv.name().global()) {
                        panic!(
                            "config '{}': service '{}' does already exist",
                            a.name(),
                            serv.name().global()
                        );
                    }
                    set.insert(serv.name().global().clone());
                }
            }
        }

        let mut subset = set.clone();
        for s in parent_set.iter() {
            if !subset.contains(s) {
                subset.insert(s.clone());
            }
        }
        for d in &self.domains {
            for a in &d.apps {
                a.check_services(&subset);
            }
        }

        for sess in self.sessions() {
            if !set.contains(sess.name().global()) && !parent_set.contains(sess.name().global()) {
                panic!(
                    "config '{}': service '{}' does not exist",
                    self.name(),
                    sess.name().global()
                );
            }
        }
    }

    fn check_gates(&self) {
        let mut map = BTreeMap::new();
        for d in &self.domains {
            for a in &d.apps {
                for rgate in a.rgates() {
                    if map.contains_key(rgate.name().global()) {
                        panic!(
                            "config '{}': rgate '{}' does already exist",
                            a.name(),
                            rgate.name().global()
                        );
                    }
                    map.insert(rgate.name().global().clone(), rgate.slots());
                }
            }
        }

        for d in &self.domains {
            for a in &d.apps {
                a.check_gates();

                for sgate in a.sgates() {
                    match map.get_mut(sgate.name().global()) {
                        Some(s) => {
                            if *s == 0 {
                                panic!(
                                    "config '{}': not enough slots in rgate '{}'",
                                    a.name(),
                                    sgate.name().global()
                                );
                            }
                            *s -= 1;
                        },
                        None => panic!(
                            "config '{}': rgate '{}' does not exist",
                            a.name(),
                            sgate.name().global()
                        ),
                    }
                }
            }
        }
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
        if let Some(ref hash) = self.hash {
            writeln!(f, "{:0w$}Hash[{}],", "", hash, w = layer + 2)?;
        }
        if let Some(eps) = self.eps {
            writeln!(f, "{:0w$}Endpoints[count={}],", "", eps, w = layer + 2)?;
        }
        if let Some(t) = self.time {
            writeln!(f, "{:0w$}TimeSlice[{} ns],", "", t, w = layer + 2)?;
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
        for m in &self.phys_mems {
            writeln!(
                f,
                "{:0w$}PhysMem[addr={:#x}, size={:#x} KiB, perm={:?}],",
                "",
                m.phys(),
                m.size() / 1024,
                m.perm(),
                w = layer + 2
            )?;
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
                writeln!(f, "{:0w$}Domain on {} [", "", d.tile.0, w = layer + 2)?;
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
