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

use m3::boxed::Box;
use m3::cap::Selector;
use m3::cell::{RefCell, StaticRefCell};
use m3::cfg::PAGE_SIZE;
use m3::col::{String, ToString, Vec};
use m3::com::MemGate;
use m3::errors::{Code, Error, VerboseError};
use m3::format;
use m3::goff;
use m3::kif::{boot, CapRngDesc, CapType, Perm, FIRST_FREE_SEL};
use m3::log;
use m3::mem::{size_of, GlobAddr};
use m3::rc::Rc;
use m3::server::DEF_MAX_CLIENTS;
use m3::tcu::{TileId, MEM_BW_UNLIMITED};
use m3::tiles::{Activity, ChildActivity, Tile};
use m3::util::math;

use crate::childs;
use crate::config;
use crate::gates;
use crate::memory;
use crate::sems;
use crate::services;
use crate::tiles;

//
// Our parent/kernel initializes our cap space as follows:
// +-----------+--------+-------+-----+-----------+--------+-----+------------+-------+-----+-----------+
// | boot info | serial | mod_0 | ... | mod_{n-1} | tile_0 | ... | tile_{n-1} | mem_0 | ... | mem_{n-1} |
// +-----------+--------+-------+-----+-----------+--------+-----+------------+-------+-----+-----------+
// ^-- FIRST_FREE_SEL
//
const SUBSYS_SELS: Selector = FIRST_FREE_SEL;

const DEF_TIME_SLICE: u64 = 1_000_000; // 1ms
const OUR_EPS: u32 = 16;

pub(crate) const SERIAL_RGATE_SEL: Selector = SUBSYS_SELS + 1;

static OUR_TILE: StaticRefCell<Option<Rc<tiles::TileUsage>>> = StaticRefCell::new(None);
// use Box here, because we also store them in the ChildManager, which expects them to be boxed
#[allow(clippy::vec_box)]
static DELAYED: StaticRefCell<Vec<Box<childs::OwnChild>>> = StaticRefCell::new(Vec::new());

pub struct Arguments {
    pub max_clients: usize,
    sems: Vec<String>,
}

impl Default for Arguments {
    fn default() -> Self {
        Self {
            max_clients: DEF_MAX_CLIENTS,
            sems: Vec::new(),
        }
    }
}

pub struct Subsystem {
    info: boot::Info,
    mods: Vec<boot::Mod>,
    tiles: Vec<boot::Tile>,
    mems: Vec<boot::Mem>,
    servs: Vec<boot::Service>,
    cfg_str: String,
    cfg: config::AppConfig,
}

impl Subsystem {
    pub fn new() -> Result<Self, Error> {
        let mgate = MemGate::new_bind(SUBSYS_SELS);
        let mut off: goff = 0;

        let info: boot::Info = mgate.read_obj(0)?;
        off += size_of::<boot::Info>() as goff;

        let mods = mgate.read_into_vec::<boot::Mod>(info.mod_count as usize, off)?;
        off += size_of::<boot::Mod>() as goff * info.mod_count;

        let tiles = mgate.read_into_vec::<boot::Tile>(info.tile_count as usize, off)?;
        off += size_of::<boot::Tile>() as goff * info.tile_count;

        let mems = mgate.read_into_vec::<boot::Mem>(info.mem_count as usize, off)?;
        off += size_of::<boot::Mem>() as goff * info.mem_count;

        let servs = mgate.read_into_vec::<boot::Service>(info.serv_count as usize, off)?;

        let cfg = Self::parse_config(&mods)?;

        Self::create_rgates(&cfg.1)?;

        let sub = Self {
            info,
            mods,
            tiles,
            mems,
            servs,
            cfg_str: cfg.0,
            cfg: cfg.1,
        };
        sub.init();
        Ok(sub)
    }

    fn init(&self) {
        log!(crate::LOG_SUBSYS, "Boot modules:");
        for m in self.mods() {
            log!(crate::LOG_SUBSYS, "  {:?}", m);
        }

        log!(crate::LOG_SUBSYS, "Available tiles:");
        let mut tiles = Vec::new();
        for (i, tile) in self.tiles().iter().enumerate() {
            log!(crate::LOG_SUBSYS, "  {:?}", tile);
            tiles.push((tile.id as TileId, self.get_tile(i)));
        }
        tiles::create(tiles);

        log!(crate::LOG_SUBSYS, "Available memory:");
        for (i, mem) in self.mems().iter().enumerate() {
            let mem_mod = Rc::new(memory::MemMod::new(
                self.get_mem(i),
                mem.addr(),
                mem.size(),
                mem.reserved(),
            ));
            log!(crate::LOG_SUBSYS, "  {:?}", mem_mod);
            memory::container().add(mem_mod);
        }

        if !self.services().is_empty() {
            log!(crate::LOG_SUBSYS, "Services:");
            for (i, s) in self.services().iter().enumerate() {
                let sel = self.get_service(i);
                log!(
                    crate::LOG_SUBSYS,
                    "  Service[name={}, sessions={}]",
                    s.name(),
                    s.sessions()
                );
                services::add_service(
                    childs::Id::MAX,
                    sel,
                    sel + 1,
                    s.name().to_string(),
                    s.sessions(),
                    false,
                )
                .unwrap();
            }
        }

        if Activity::own().resmng().is_none() {
            log!(crate::LOG_CFG, "Parsed {:?}", self.cfg);
        }
    }

    fn parse_config(mods: &[boot::Mod]) -> Result<(String, config::AppConfig), Error> {
        let mut cfg_mem: Option<(usize, goff)> = None;

        // find boot config
        for (id, m) in mods.iter().enumerate() {
            if m.name() == "boot.xml" {
                cfg_mem = Some((id, m.size));
                continue;
            }
        }

        // read boot config
        let cfg_mem = cfg_mem.unwrap();
        let memgate = MemGate::new_bind(SUBSYS_SELS + 2 + cfg_mem.0 as Selector);
        let xml = memgate.read_into_vec::<u8>(cfg_mem.1 as usize, 0)?;

        // parse boot config
        let xml_str = String::from_utf8(xml).map_err(|_| Error::new(Code::InvArgs))?;
        let cfg = config::AppConfig::parse(&xml_str)?;
        Ok((xml_str, cfg))
    }

    fn create_rgates(cfg: &config::AppConfig) -> Result<(), Error> {
        for dom in cfg.domains() {
            for a in dom.apps() {
                for rgate in a.rgates() {
                    gates::get().add_rgate(
                        rgate.name().global().clone(),
                        rgate.msg_size(),
                        rgate.slots(),
                    )?;
                }
            }
        }
        Ok(())
    }

    pub fn parse_args(&self) -> Arguments {
        let mut args = Arguments::default();
        for arg in self.cfg().args() {
            if let Some(clients) = arg.strip_prefix("maxcli=") {
                args.max_clients = clients
                    .parse::<usize>()
                    .expect("Failed to parse client count");
            }
            else if let Some(sem) = arg.strip_prefix("sem=") {
                args.sems.push(sem.to_string());
            }
        }
        args
    }

    pub fn cfg_str(&self) -> &String {
        &self.cfg_str
    }

    pub fn cfg(&self) -> &config::AppConfig {
        &self.cfg
    }

    pub fn info(&self) -> &boot::Info {
        &self.info
    }

    pub fn mods(&self) -> &Vec<boot::Mod> {
        &self.mods
    }

    pub fn tiles(&self) -> &Vec<boot::Tile> {
        &self.tiles
    }

    pub fn mems(&self) -> &Vec<boot::Mem> {
        &self.mems
    }

    pub fn services(&self) -> &Vec<boot::Service> {
        &self.servs
    }

    pub fn get_mod(&self, idx: usize) -> MemGate {
        MemGate::new_bind(SUBSYS_SELS + 2 + idx as Selector)
    }

    pub fn get_tile(&self, idx: usize) -> Rc<Tile> {
        Rc::new(Tile::new_bind(
            self.tiles[idx].id as TileId,
            self.tiles[idx].desc,
            SUBSYS_SELS + 2 + (self.mods.len() + idx) as Selector,
        ))
    }

    pub fn get_mem(&self, idx: usize) -> MemGate {
        MemGate::new_bind(SUBSYS_SELS + 2 + (self.mods.len() + self.tiles.len() + idx) as Selector)
    }

    pub fn get_service(&self, idx: usize) -> Selector {
        SUBSYS_SELS
            + 2
            + (self.mods.len() + self.tiles.len() + self.mems.len() + idx * 2) as Selector
    }

    pub fn start<S>(&self, mut spawn: S) -> Result<(), VerboseError>
    where
        S: FnMut(&mut childs::OwnChild) -> Result<(), VerboseError>,
    {
        let root = self.cfg();
        if Activity::own().resmng().is_none() {
            root.check();
        }

        let args = self.parse_args();
        for sem in &args.sems {
            sems::get()
                .add_sem(sem.clone())
                .expect("Unable to add semaphore");
        }

        // keep our own tile to make sure that we allocate a different one for the next domain in case
        // our domain contains just ourself.
        if !root.domains().first().unwrap().pseudo {
            OUR_TILE.replace(Some(Rc::new(
                tiles::get()
                    .find_and_alloc(Activity::own().tile_desc())
                    .map_err(|e| {
                        VerboseError::new(e.code(), "Unable to allocate own tile".to_string())
                    })?,
            )));
        }
        else if !Activity::own().tile_desc().has_virtmem() {
            panic!("Can't share tile without VM support");
        }

        // determine default mem and kmem per child
        let (def_kmem, def_umem) = split_mem(root)?;

        let mut mem_id = 1;

        for (idx, d) in root.domains().iter().enumerate() {
            // allocate new tile; root allocates from its own set, others ask their resmng
            let tile_usage = if d.pseudo || Activity::own().resmng().is_none() {
                Rc::new(
                    tiles::get()
                        .find_and_alloc_with_desc(&d.tile.0)
                        .map_err(|e| {
                            VerboseError::new(
                                e.code(),
                                format!(
                                    "Unable to allocate tile for domain {} with {}",
                                    idx, d.tile.0
                                ),
                            )
                        })?,
                )
            }
            else {
                let child_tile = Tile::get(&d.tile.0).map_err(|e| {
                    VerboseError::new(e.code(), format!("Unable to get tile {}", d.tile.0))
                })?;
                Rc::new(tiles::TileUsage::new_obj(child_tile))
            };

            // memory pool for the domain
            let dom_mem = d.apps().iter().fold(0, |sum, a| {
                sum + a.user_mem().unwrap_or(def_umem as usize) as goff
            });
            let mem_pool = Rc::new(RefCell::new(
                memory::container().alloc_pool(dom_mem).map_err(|e| {
                    VerboseError::new(
                        e.code(),
                        format!("Unable to allocate memory pool with {} b", dom_mem),
                    )
                })?,
            ));

            // if the activities should run on our own tile, all PMP EPs are already installed
            if tile_usage.tile_id() != Activity::own().tile_id() {
                // add regions to PMP
                for slice in mem_pool.borrow().slices() {
                    tile_usage
                        .add_mem_region(slice.derive()?, slice.capacity() as usize, true)
                        .map_err(|e| {
                            VerboseError::new(e.code(), "Unable to add PMP region".to_string())
                        })?;
                }

                // if we're root, we need to provide the tile access to boot modules as well
                if Activity::own().resmng().is_none() {
                    let start_addr = self.mods[0].addr();
                    let last_mod = &self.mods[self.mods.len() - 1];
                    let end_addr = last_mod.addr() + last_mod.size;
                    let mod_size = end_addr.offset() - start_addr.offset();
                    // boot modules need RW for data segment (every activity gets its own module)
                    let mod_slice = memory::container()
                        .find_mem(start_addr.offset(), mod_size, Perm::RW)
                        .map_err(|e| {
                            VerboseError::new(
                                e.code(),
                                format!(
                                    "Unable to find memory region for boot module {:#x}..{:#x}",
                                    start_addr.offset(),
                                    start_addr.offset() + mod_size
                                ),
                            )
                        })?;
                    tile_usage
                        .add_mem_region(mod_slice.derive()?, mod_size as usize, true)
                        .map_err(|e| {
                            VerboseError::new(
                                e.code(),
                                "Unable to add PMP region for boot mods".to_string(),
                            )
                        })?;
                }
            }
            else {
                // don't install new PMP EPs, but remember our whole memory areas to inherit them
                // later to allocated tiles. TODO we could improve that by only providing them access
                // to the memory pool of the child that allocates the tile, though.
                for m in memory::container().mods() {
                    tile_usage
                        .add_mem_region(
                            m.mgate().derive(0, m.capacity() as usize, Perm::RWX)?,
                            m.capacity() as usize,
                            false,
                        )
                        .unwrap();
                }
            }

            // split available PTs according to the config
            let tile_quota = tile_usage.tile_obj().quota()?;
            let (mut pt_sharer, shared_pts) = split_pts(tile_quota.page_tables().left(), d);

            let mut domain_total_eps = tile_quota.endpoints().left();
            let mut domain_total_bw = 0;
            let mut domain_total_time = 0;
            let mut domain_total_pts = 0;
            let mut domain_kmem_bytes = 0;

            // account for ourself, if we share this tile
            if tile_usage.tile_id() == Activity::own().tile_id() {
                pt_sharer += 1;
                domain_total_eps -= OUR_EPS;
            }

            for cfg in d.apps() {
                // accumulate memory bandwidth, child time, pts, and kmem
                domain_total_bw = match (cfg.mem_bw, domain_total_bw) {
                    // if it's already unlimited, keep that
                    (_, cur) if cur == MEM_BW_UNLIMITED => MEM_BW_UNLIMITED,
                    // if not and there is a bandwidth specified, accumulate them
                    (Some(bw), cur) => cur + bw.rate,
                    // if there is no bandwidth specified, we need unlimited
                    (None, _) => MEM_BW_UNLIMITED,
                };
                domain_total_time += cfg.time.unwrap_or(DEF_TIME_SLICE);
                domain_total_pts += cfg.pts.unwrap_or(shared_pts / pt_sharer);
                domain_kmem_bytes += cfg.kern_mem.unwrap_or(def_kmem);

                // add requested physical memory regions to pool
                for mem in cfg.phys_mems() {
                    let mslice = memory::container()
                        .find_mem(mem.phys(), mem.size(), mem.perm())
                        .map_err(|e| {
                            VerboseError::new(
                                e.code(),
                                format!(
                                    "Unable to find physical memory {:#x}..{:#x} with {:?}",
                                    mem.phys(),
                                    mem.phys() + mem.size(),
                                    mem.perm()
                                ),
                            )
                        })?;
                    mem_pool.borrow_mut().add(mslice);
                }
            }

            // derive kmem for the entire domain. All apps that did not specify a kmem quota will
            // share this domain kmem.
            let domain_kmem = Activity::own()
                .kmem()
                .derive(domain_kmem_bytes)
                .map_err(|e| {
                    VerboseError::new(
                        e.code(),
                        format!("Unable to derive {}b of kernel memory", domain_kmem_bytes),
                    )
                })?;

            // create user mem pool for entire domain
            let domain_umem = childs::ChildMem::new(mem_id, mem_pool.clone(), def_umem);
            mem_id += 1;

            // account for ourself, if we share this tile
            let child_total_time = if tile_usage.tile_id() == Activity::own().tile_id() {
                domain_total_time + DEF_TIME_SLICE
            }
            else {
                domain_total_time
            };

            // set initial quota for this tile
            tile_usage
                .tile_obj()
                .set_quota(
                    MEM_BW_UNLIMITED, // TileMux is currently not restricted
                    child_total_time,
                    tile_quota.page_tables().total(),
                )
                .map_err(|e| {
                    VerboseError::new(
                        e.code(),
                        format!(
                            "Unable to set quota for tile to time={}, pts={}",
                            child_total_time,
                            tile_quota.page_tables().total()
                        ),
                    )
                })?;

            // derive a new tile object for the entire domain (so that they cannot change the PMP EPs)
            let domain_pe_usage = if d.apps().iter().next().unwrap().domains().is_empty() {
                let domain_eps = Some(domain_total_eps);
                let domain_bw = if domain_total_bw > 0 {
                    Some(domain_total_bw)
                }
                else {
                    None
                };
                let domain_time = Some(domain_total_time);
                let domain_pts = Some(domain_total_pts);

                Some(Rc::new(
                    tile_usage
                        .derive(domain_eps, domain_bw, domain_time, domain_pts)
                        .map_err(|e| {
                            VerboseError::new(
                                e.code(),
                                format!(
                                    "Unable to derive new tile with eps={:?}, bw={:?}, time={:?}, pts={:?}",
                                    domain_eps, domain_bw, domain_time, domain_pts,
                                ),
                            )
                        })?,
                ))
            }
            else {
                None
            };

            for cfg in d.apps() {
                // determine tile object with potentially reduced number of EPs
                let (domain_tile_usage, child_pe_usage) = if !cfg.domains().is_empty() {
                    // a resource manager has to be able to set PMPs and thus needs the root tile
                    (None, tile_usage.clone())
                }
                else if cfg.eps.is_some()
                    || cfg.mem_bw.is_some()
                    || cfg.time.is_some()
                    || cfg.pts.is_some()
                {
                    // if the child wants any specific quota, derive from the base tile object
                    let base = domain_pe_usage.as_ref().unwrap();
                    (
                        // keep the base object around in case there are no other children using it
                        Some(base.clone()),
                        Rc::new(
                            base.derive(cfg.eps, cfg.mem_bw.map(|bw| bw.rate), cfg.time, cfg.pts)
                                .map_err(|e| {
                                    VerboseError::new(
                                        e.code(),
                                        format!(
                                            "Unable to derive new tile with eps={:?}, bw={:?}, time={:?}, pts={:?}",
                                            cfg.eps, cfg.mem_bw, cfg.time, cfg.pts,
                                        ),
                                    )
                                })?,
                        ),
                    )
                }
                else {
                    // without specified restrictions, childs share their resource quota
                    (None, domain_pe_usage.as_ref().unwrap().clone())
                };

                // kernel memory for child
                let kmem = if cfg.kernel_mem().is_none() {
                    domain_kmem.clone()
                }
                else {
                    let kmem_bytes = cfg.kernel_mem().unwrap_or(def_kmem);
                    domain_kmem.derive(kmem_bytes).map_err(|e| {
                        VerboseError::new(
                            e.code(),
                            format!("Unable to derive {}b of kernel memory", kmem_bytes),
                        )
                    })?
                };

                // determine user memory for child
                let child_mem = if let Some(umem) = cfg.user_mem() {
                    mem_id += 1;
                    childs::ChildMem::new(mem_id - 1, domain_umem.pool().clone(), umem as goff)
                }
                else {
                    domain_umem.clone()
                };

                let sub = if !cfg.domains().is_empty() {
                    // TODO currently, we don't support tile sharing of a resource manager and another
                    // activities on the same level. The resource manager needs to set PMP EPs and might
                    // thus interfere with the other activities.
                    assert!(
                        child_pe_usage.tile_id() != Activity::own().tile_id()
                            && d.apps().len() == 1
                    );

                    // create MemGate for config substring
                    let cfg_range = cfg.cfg_range();
                    let cfg_len = cfg_range.1 - cfg_range.0;
                    let cfg_slice =
                        memory::container()
                            .alloc_mem(cfg_len as goff)
                            .map_err(|e| {
                                VerboseError::new(
                                    e.code(),
                                    format!("Unable to allocate {}b for config", cfg_len),
                                )
                            })?;
                    let cfg_mem = cfg_slice.derive()?;
                    cfg_mem.write(self.cfg_str()[cfg_range.0..cfg_range.1].as_bytes(), 0)?;

                    let mut sub = SubsystemBuilder::new((cfg_mem, cfg_slice.addr(), cfg_len));

                    // add tiles
                    sub.add_tile(child_pe_usage.tile_id(), child_pe_usage.tile_obj().clone());
                    pass_down_tiles(&mut sub, cfg);

                    // serial rgate
                    pass_down_serial(&mut sub, cfg);

                    // split off the grandchild memories; allocate them from the child quota
                    let old_umem_quota = child_mem.quota();
                    split_child_mem(cfg, &child_mem);
                    // determine memory size for the entire subsystem
                    let sub_mem = old_umem_quota - child_mem.quota();

                    // add memory
                    let sub_slice = mem_pool.borrow_mut().allocate_slice(sub_mem).map_err(|e| {
                        VerboseError::new(
                            e.code(),
                            format!("Unable to allocate {}b for subsys", sub_mem),
                        )
                    })?;
                    sub.add_mem(
                        sub_slice.derive()?,
                        sub_slice.addr(),
                        sub_slice.capacity(),
                        sub_slice.in_reserved_mem(),
                    );
                    pass_down_mem(&mut sub, cfg)?;

                    // add services
                    for s in cfg.sess_creators() {
                        let (sess_frac, sess_fixed) = split_sessions(root, s.serv_name());
                        sub.add_serv(s.serv_name().clone(), sess_frac, sess_fixed, s.sess_count());
                    }

                    Some(sub)
                }
                else {
                    None
                };

                let child_id = childs::borrow_mut().alloc_id();
                let mut child = Box::new(childs::OwnChild::new(
                    child_id,
                    tile_usage.clone(),
                    domain_tile_usage,
                    child_pe_usage,
                    // TODO either remove args and daemon from config or remove the clones from OwnChild
                    cfg.args().clone(),
                    cfg.daemon(),
                    kmem,
                    child_mem,
                    cfg.clone(),
                    sub,
                ));
                log!(crate::LOG_CHILD, "Created {:?}", child);

                if child.has_unmet_reqs() {
                    DELAYED.borrow_mut().push(child);
                }
                else {
                    spawn(&mut child)?;
                    childs::borrow_mut().add(child);
                }
            }
        }
        Ok(())
    }
}

pub struct SubsystemBuilder {
    _desc: Option<MemGate>,
    cfg: (MemGate, GlobAddr, usize),
    tiles: Vec<(TileId, Rc<Tile>)>,
    mems: Vec<(MemGate, GlobAddr, goff, bool)>,
    servs: Vec<(String, u32, u32, Option<u32>)>,
    serv_objs: Vec<services::Service>,
    serial: bool,
}

impl SubsystemBuilder {
    pub fn new(cfg: (MemGate, GlobAddr, usize)) -> Self {
        Self {
            _desc: None,
            cfg,
            tiles: Vec::new(),
            mems: Vec::new(),
            servs: Vec::new(),
            serv_objs: Vec::new(),
            serial: false,
        }
    }

    pub fn add_tile(&mut self, id: TileId, tile: Rc<Tile>) {
        self.tiles.push((id, tile));
    }

    pub fn add_mem(&mut self, mem: MemGate, addr: GlobAddr, size: goff, reserved: bool) {
        self.mems.push((mem, addr, size, reserved));
    }

    pub fn add_serv(&mut self, name: String, sess_frac: u32, sess_fixed: u32, quota: Option<u32>) {
        if !self.servs.iter().any(|s| s.0 == name) {
            self.servs.push((name, sess_frac, sess_fixed, quota));
        }
    }

    pub fn add_serial(&mut self) {
        self.serial = true;
    }

    pub fn desc_size(&self) -> usize {
        size_of::<boot::Info>()
            + size_of::<boot::Mod>() * 1
            + size_of::<boot::Tile>() * self.tiles.len()
            + size_of::<boot::Mem>() * self.mems.len()
            + size_of::<boot::Service>() * self.servs.len()
    }

    pub fn finalize_async(
        &mut self,
        child: childs::Id,
        act: &mut ChildActivity,
    ) -> Result<(), VerboseError> {
        let mut sel = SUBSYS_SELS;
        let mut off: goff = 0;

        let mut mem = memory::container()
            .alloc_mem(self.desc_size() as goff)
            .map_err(|e| {
                VerboseError::new(
                    e.code(),
                    format!("Unable to allocate {}b for subsys info", self.desc_size()),
                )
            })?
            .derive()?;

        // boot info
        let info = boot::Info {
            mod_count: 1,
            tile_count: self.tiles.len() as u64,
            mem_count: self.mems.len() as u64,
            serv_count: self.servs.len() as u64,
        };
        mem.write_obj(&info, off)?;
        act.delegate_to(CapRngDesc::new(CapType::OBJECT, mem.sel(), 1), sel)?;
        off += size_of::<boot::Info>() as goff;
        sel += 1;

        // serial rgate
        if self.serial {
            act.delegate_to(CapRngDesc::new(CapType::OBJECT, SERIAL_RGATE_SEL, 1), sel)?;
        }
        sel += 1;

        // boot module for config
        let m = boot::Mod::new(self.cfg.1, self.cfg.2 as u64, "boot.xml");
        mem.write_obj(&m, off)?;
        act.delegate_to(CapRngDesc::new(CapType::OBJECT, self.cfg.0.sel(), 1), sel)?;
        off += size_of::<boot::Mod>() as goff;
        sel += 1;

        // tiles
        for (id, tile) in &self.tiles {
            let boot_tile = boot::Tile::new(*id as u32, tile.desc());
            mem.write_obj(&boot_tile, off)?;

            act.delegate_to(CapRngDesc::new(CapType::OBJECT, tile.sel(), 1), sel)?;

            off += size_of::<boot::Tile>() as goff;
            sel += 1;
        }

        // memory regions
        for (mgate, addr, size, reserved) in &self.mems {
            let boot_mem = boot::Mem::new(*addr, *size, *reserved);
            mem.write_obj(&boot_mem, off)?;

            act.delegate_to(CapRngDesc::new(CapType::OBJECT, mgate.sel(), 1), sel)?;

            off += size_of::<boot::Mem>() as goff;
            sel += 1;
        }

        // services
        for (name, sess_frac, sess_fixed, sess_quota) in &self.servs {
            let serv = services::get_by_name(name).unwrap();
            let sessions = if let Some(quota) = sess_quota {
                *quota
            }
            else {
                if *sess_frac > (serv.sessions() - sess_fixed) {
                    return Err(VerboseError::new(
                        Code::NoSpace,
                        format!(
                            "Insufficient session quota for {} (have {}, need {})",
                            name,
                            serv.sessions() - sess_fixed,
                            *sess_frac
                        ),
                    ));
                }
                (serv.sessions() - sess_fixed) / sess_frac
            };
            let subserv = services::Service::derive_async(serv, child, sessions).map_err(|e| {
                VerboseError::new(e.code(), format!("Unable to derive from service {}", name))
            })?;
            let boot_serv = boot::Service::new(name, sessions);
            mem.write_obj(&boot_serv, off)?;

            act.delegate_to(CapRngDesc::new(CapType::OBJECT, subserv.sel(), 1), sel)?;
            act.delegate_to(
                CapRngDesc::new(CapType::OBJECT, subserv.sgate_sel(), 1),
                sel + 1,
            )?;

            off += size_of::<boot::Service>() as goff;
            sel += 2;

            self.serv_objs.push(subserv);
        }

        // deactivate the memory gates so that the child can activate them for itself
        self.cfg.0.deactivate();
        mem.deactivate();

        self._desc = Some(mem);
        Ok(())
    }
}

pub(crate) fn start_delayed_async<S>(mut spawn_async: S) -> Result<(), VerboseError>
where
    S: FnMut(&mut childs::OwnChild) -> Result<(), VerboseError>,
{
    let mut new_wait = false;
    let mut idx = 0;
    while idx < DELAYED.borrow().len() {
        if DELAYED.borrow()[idx].has_unmet_reqs() {
            idx += 1;
            continue;
        }

        let mut child = DELAYED.borrow_mut().remove(idx);
        spawn_async(&mut child)?;
        childs::borrow_mut().add(child);
        new_wait = true;
    }

    if new_wait {
        childs::borrow_mut().start_waiting(1);
    }
    Ok(())
}

fn pass_down_tiles(sub: &mut SubsystemBuilder, app: &config::AppConfig) {
    for d in app.domains() {
        for child in d.apps() {
            for tile in child.tiles() {
                for _ in 0..tile.count() {
                    if let Some(idx) = tiles::get().find_with_desc(&tile.tile_type().0) {
                        tiles::get().alloc(idx);
                        sub.add_tile(tiles::get().id(idx), tiles::get().get(idx));
                    }
                }
            }

            pass_down_tiles(sub, child);
        }
    }
}

fn pass_down_serial(sub: &mut SubsystemBuilder, app: &config::AppConfig) {
    for d in app.domains() {
        for child in d.apps() {
            if child.serial.is_some() {
                sub.add_serial();
            }
            pass_down_serial(sub, child);
        }
    }
}

fn pass_down_mem(sub: &mut SubsystemBuilder, app: &config::AppConfig) -> Result<(), VerboseError> {
    for d in app.domains() {
        for child in d.apps() {
            for pmem in child.phys_mems() {
                let slice = memory::container()
                    .find_mem(pmem.phys(), pmem.size(), Perm::RW)
                    .map_err(|e| {
                        VerboseError::new(
                            e.code(),
                            format!(
                                "Unable to find memory {:#x}..{:#x} for subsys",
                                pmem.phys(),
                                pmem.phys() + pmem.size()
                            ),
                        )
                    })?;
                let mgate = slice.derive()?;
                // TODO determine memory id
                let glob = GlobAddr::new_with(0, pmem.phys());
                sub.add_mem(mgate, glob, pmem.size(), true);
            }

            pass_down_mem(sub, child)?;
        }
    }
    Ok(())
}

fn split_child_mem(cfg: &config::AppConfig, mem: &Rc<childs::ChildMem>) {
    let mut def_childs = 0;
    for d in cfg.domains() {
        for a in d.apps() {
            if let Some(cmem) = a.user_mem() {
                mem.alloc_mem(cmem as goff);
            }
            else {
                def_childs += 1;
            }
        }
    }
    let per_child = mem.quota() / (def_childs + 1);
    mem.alloc_mem(per_child * def_childs);
}

fn split_mem(cfg: &config::AppConfig) -> Result<(usize, goff), VerboseError> {
    let mut total_umem = memory::container().capacity();
    let mut total_kmem = Activity::own().kmem().quota()?.total();

    let mut total_kparties = cfg.count_apps() + 1;
    let mut total_mparties = total_kparties;
    for d in cfg.domains() {
        for a in d.apps() {
            if let Some(kmem) = a.kernel_mem() {
                if total_kmem < kmem {
                    return Err(VerboseError::new(
                        Code::OutOfMem,
                        format!(
                            "Insufficient kernel memory (need {}, have {})",
                            kmem, total_kmem
                        ),
                    ));
                }
                total_kmem -= kmem;
                total_kparties -= 1;
            }

            if let Some(amem) = a.user_mem() {
                if total_umem < amem as goff {
                    return Err(VerboseError::new(
                        Code::OutOfMem,
                        format!(
                            "Insufficient user memory (need {}, have {})",
                            amem, total_umem
                        ),
                    ));
                }
                total_umem -= amem as goff;
                total_mparties -= 1;
            }
        }
    }

    let def_kmem = total_kmem / total_kparties;
    let def_umem = math::round_dn(total_umem / total_mparties as goff, PAGE_SIZE as goff);
    Ok((def_kmem, def_umem))
}

fn split_sessions(cfg: &config::AppConfig, name: &str) -> (u32, u32) {
    let mut frac = 0;
    let mut fixed = 0;
    for d in cfg.domains() {
        for a in d.apps() {
            for sess in a.sessions() {
                if sess.name().global() == name {
                    frac += 1;
                }
            }
            for sess in a.sess_creators() {
                if sess.serv_name() == name {
                    if let Some(n) = sess.sess_count() {
                        fixed += n;
                    }
                    else {
                        frac += 1;
                    }
                }
            }
        }
    }
    (frac, fixed)
}

fn split_pts(total_pts: usize, d: &config::Domain) -> (usize, usize) {
    let mut pt_sharer = 0;
    let mut rem_pts = total_pts;
    for cfg in d.apps() {
        match cfg.pts {
            Some(n) => {
                assert!(rem_pts >= n);
                rem_pts -= n;
            },
            None => pt_sharer += 1,
        }
    }
    (pt_sharer, rem_pts)
}
