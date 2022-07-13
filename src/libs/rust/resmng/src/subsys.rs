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
use m3::cell::RefCell;
use m3::cfg::{self, PAGE_SIZE};
use m3::col::{String, ToString, Vec};
use m3::com::MemGate;
use m3::errors::{Code, Error, VerboseError};
use m3::format;
use m3::io::LogFlags;
use m3::kif::{boot, CapRngDesc, CapType, Perm, TileDesc, FIRST_FREE_SEL};
use m3::log;
use m3::mem::{size_of, GlobOff};
use m3::rc::Rc;
use m3::server::DEF_MAX_CLIENTS;
use m3::tcu::{TileId, MEM_BW_UNLIMITED};
use m3::tiles::{Activity, ChildActivity, Tile, TileArgs};
use m3::time::TimeDuration;
use m3::util::math;

use crate::childs;
use crate::config;
use crate::config::validator;
use crate::requests::Requests;
use crate::resources::{memory, mods, services, tiles, Resources};

//
// Our parent/kernel initializes our cap space as follows:
// +-----------+--------+-------+-----+-----------+--------+-----+------------+-------+-----+-----------+
// | boot info | serial | mod_0 | ... | mod_{n-1} | tile_0 | ... | tile_{n-1} | mem_0 | ... | mem_{n-1} |
// +-----------+--------+-------+-----+-----------+--------+-----+------------+-------+-----+-----------+
// ^-- FIRST_FREE_SEL
//
const SUBSYS_SELS: Selector = FIRST_FREE_SEL;

const DEF_RESMNG_MEM: GlobOff = 32 * 1024 * 1024;
const DEF_TIME_SLICE: TimeDuration = TimeDuration::from_millis(1);
const OUR_EPS: u32 = 16;

pub(crate) const SERIAL_RGATE_SEL: Selector = SUBSYS_SELS + 1;

pub struct Arguments {
    pub max_clients: usize,
    pub sems: Vec<String>,
}

impl Default for Arguments {
    fn default() -> Self {
        Self {
            max_clients: DEF_MAX_CLIENTS,
            sems: Vec::new(),
        }
    }
}

pub trait ChildStarter {
    /// Returns a [`MemGate`] for the boot module with given name
    fn get_bootmod(&mut self, name: &str) -> Result<MemGate, Error> {
        MemGate::new_bind_bootmod(name)
    }

    /// Creates a new activity for the given child and starts it
    #[allow(m3_async::no_async_call)]
    fn start_async(
        &mut self,
        reqs: &Requests,
        res: &mut Resources,
        child: &mut childs::OwnChild,
    ) -> Result<(), VerboseError>;

    /// Prepares the tiles for the given domain (e.g., installs additional PMP EPs)
    fn configure_tile(
        &mut self,
        res: &mut Resources,
        tile: &mut tiles::TileUsage,
        domain: &config::Domain,
    ) -> Result<(), VerboseError>;
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
    pub fn new() -> Result<(Self, Resources), Error> {
        let mut res = Resources::default();
        let mgate = MemGate::new_bind(SUBSYS_SELS);
        let mut off: GlobOff = 0;

        let info: boot::Info = mgate.read_obj(0)?;
        off += size_of::<boot::Info>() as GlobOff;

        let mods = mgate.read_into_vec::<boot::Mod>(info.mod_count as usize, off)?;
        off += size_of::<boot::Mod>() as GlobOff * info.mod_count;

        let tiles = mgate.read_into_vec::<boot::Tile>(info.tile_count as usize, off)?;
        off += size_of::<boot::Tile>() as GlobOff * info.tile_count;

        let mems = mgate.read_into_vec::<boot::Mem>(info.mem_count as usize, off)?;
        off += size_of::<boot::Mem>() as GlobOff * info.mem_count;

        let servs = mgate.read_into_vec::<boot::Service>(info.serv_count as usize, off)?;

        let cfg = Self::parse_config(&mods)?;
        let sub = Self {
            info,
            mods,
            tiles,
            mems,
            servs,
            cfg_str: cfg.0,
            cfg: cfg.1,
        };

        sub.init(&mut res)?;

        Ok((sub, res))
    }

    fn init(&self, res: &mut Resources) -> Result<(), Error> {
        log!(LogFlags::Info, "Boot modules:");
        for (i, m) in self.mods().iter().enumerate() {
            log!(LogFlags::Info, "  {:?}", m);
            res.mods_mut().add(i, m);
        }

        log!(LogFlags::Info, "Available tiles:");
        for (i, tile) in self.tiles().iter().enumerate() {
            log!(LogFlags::Info, "  {:?}", tile);
            res.tiles_mut().add(self.get_tile(i));
        }

        log!(LogFlags::Info, "Available memory:");
        for (i, mem) in self.mems().iter().enumerate() {
            let mem_mod = Rc::new(memory::MemMod::new(
                self.get_mem(i),
                mem.addr(),
                mem.size(),
                mem.reserved(),
            ));
            log!(LogFlags::Info, "  {:?}", mem_mod);
            res.memory_mut().add(mem_mod);
        }

        if !self.services().is_empty() {
            log!(LogFlags::Info, "Services:");
            for (i, s) in self.services().iter().enumerate() {
                let sel = self.get_service(i);
                log!(
                    LogFlags::Info,
                    "  Service[name={}, sessions={}]",
                    s.name(),
                    s.sessions()
                );
                res.services_mut()
                    .add_service(
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

        for dom in self.cfg.domains() {
            for a in dom.apps() {
                for rgate in a.rgates() {
                    res.gates_mut().add_rgate(
                        rgate.name().global().clone(),
                        rgate.msg_size(),
                        rgate.slots(),
                    )?;
                }
            }
        }

        if Activity::own().resmng().is_none() {
            log!(LogFlags::Info, "Parsed {:?}", self.cfg);
        }

        Ok(())
    }

    fn parse_config(mods: &[boot::Mod]) -> Result<(String, config::AppConfig), Error> {
        let mut cfg_mem: Option<(usize, GlobOff)> = None;

        // find boot config
        for (id, m) in mods.iter().enumerate() {
            if m.name() == "boot.xml" {
                cfg_mem = Some((id, m.size));
                break;
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

    pub fn get_mod(idx: usize) -> MemGate {
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

    pub fn start_async(
        &self,
        childs: &mut childs::ChildManager,
        reqs: &Requests,
        res: &mut Resources,
        starter: &mut dyn ChildStarter,
    ) -> Result<Vec<Box<childs::OwnChild>>, VerboseError> {
        let mut delayed = Vec::new();

        let root = self.cfg();
        if Activity::own().resmng().is_none() {
            validator::validate(root, res)?;
        }

        // mark own tile as used to ensure that we allocate a different one for the next domain in
        // case our domain contains just ourself.
        if !root.domains().first().unwrap().pseudo {
            let own = res.tiles().find(Activity::own().tile_desc()).map_err(|e| {
                VerboseError::new(e.code(), "Unable to allocate own tile".to_string())
            })?;
            res.tiles().add_user(&own);
        }
        else if !Activity::own().tile_desc().has_virtmem() {
            return Err(VerboseError::new(
                Code::InvArgs,
                "Can't share tile without VM support".to_string(),
            ));
        }

        // determine default mem and kmem per child
        let (def_kmem, def_umem) = split_mem(res, root)?;

        let mut mem_id = 1;

        for (idx, dom) in root.domains().iter().enumerate() {
            // allocate new tile; root allocates from its own set, others ask their resmng
            let mut tile_usage = if dom.pseudo || Activity::own().resmng().is_none() {
                let own_desc = Activity::own().tile_desc();
                let base = TileDesc::new(own_desc.tile_type(), own_desc.isa(), 0);
                res.tiles().find_with_attr(base, &dom.tile.0).map_err(|e| {
                    VerboseError::new(
                        e.code(),
                        format!(
                            "Unable to allocate tile for domain {} with {}",
                            idx, dom.tile.0
                        ),
                    )
                })?
            }
            else {
                // don't initialize the tile here, because we want to load the multiplexer ourself
                // and also define all PMP EPs
                let child_tile = Tile::get_with(&dom.tile.0, TileArgs::default().init(false))
                    .map_err(|e| {
                        VerboseError::new(e.code(), format!("Unable to get tile {}", dom.tile.0))
                    })?;
                tiles::TileUsage::new_obj(child_tile)
            };

            // memory pool for the domain
            let dom_mem = dom.apps().iter().fold(0, |sum, a| {
                sum + a.user_mem().unwrap_or(def_umem as usize) as GlobOff
            });
            let mem_pool = Rc::new(RefCell::new(res.memory_mut().alloc_pool(dom_mem).map_err(
                |e| {
                    VerboseError::new(
                        e.code(),
                        format!("Unable to allocate memory pool with {} b", dom_mem),
                    )
                },
            )?));

            // if the activities should run on our own tile, all PMP EPs are already installed
            if tile_usage.tile_id() != Activity::own().tile_id() {
                let mux = dom.mux().unwrap_or("tilemux");
                let mux_mem = dom.mux_mem().unwrap_or(cfg::FIXED_TILEMUX_MEM);
                // load multiplexer onto tile
                tile_usage.state_mut().load_mux(
                    mux,
                    mux_mem,
                    dom.initrd(),
                    dom.dtb(),
                    |size| {
                        let mux_mem_slice = match res.memory_mut().alloc_mem(size as GlobOff) {
                            Ok(mem) => mem,
                            Err(e) => {
                                log!(
                                    LogFlags::Error,
                                    "Unable to allocate {}b for multiplexer",
                                    size
                                );
                                return Err(e);
                            },
                        };
                        mux_mem_slice.derive().map(|m| (m, None))
                    },
                    |name| match starter.get_bootmod(name) {
                        Ok(mem) => Ok(mem),
                        Err(e) => {
                            log!(
                                LogFlags::Error,
                                "Unable to get boot module {}: {:?}",
                                name,
                                e
                            );
                            Err(e)
                        },
                    },
                )?;

                // add regions to PMP
                for slice in mem_pool.borrow().slices() {
                    tile_usage
                        .state_mut()
                        .add_mem_region(slice.derive()?, slice.capacity() as usize, true, true)
                        .map_err(|e| {
                            VerboseError::new(e.code(), "Unable to add PMP region".to_string())
                        })?;
                }
            }
            else {
                // don't install new PMP EPs, but remember our whole memory areas to inherit them
                // later to allocated tiles. TODO we could improve that by only providing them access
                // to the memory pool of the child that allocates the tile, though.
                for m in res.memory().mods() {
                    tile_usage
                        .state_mut()
                        .add_mem_region(
                            m.mgate().derive(0, m.capacity() as usize, Perm::RWX)?,
                            m.capacity() as usize,
                            false,
                            false,
                        )
                        .unwrap();
                }
            }

            // let the starter do further configurations on the tile like add PMP EPs
            starter.configure_tile(res, &mut tile_usage, dom)?;

            // split available PTs according to the config
            let tile_quota = tile_usage.tile_obj().quota()?;
            let (mut pt_sharer, shared_pts) = split_pts(tile_quota.page_tables().remaining(), dom);

            let mut domain_total_eps = tile_quota.endpoints().remaining();
            let mut domain_total_bw = 0;
            let mut domain_total_time = TimeDuration::default();
            let mut domain_total_pts = 0;
            let mut domain_kmem_bytes = 0;

            // account for ourself, if we share this tile
            if tile_usage.tile_id() == Activity::own().tile_id() {
                pt_sharer += 1;
                domain_total_eps -= OUR_EPS;
            }

            for cfg in dom.apps() {
                // accumulate memory bandwidth, child time, pts, and kmem
                domain_total_bw = match (cfg.mem_bw, domain_total_bw) {
                    // if it's already unlimited, keep that
                    (_, cur) if cur == MEM_BW_UNLIMITED => MEM_BW_UNLIMITED,
                    // if not and there is a bandwidth specified, accumulate them
                    (Some(bw), cur) => cur + bw.rate,
                    // if there is no bandwidth specified, we need unlimited
                    (None, _) => MEM_BW_UNLIMITED,
                };
                domain_total_time += cfg.time().unwrap_or(DEF_TIME_SLICE);
                domain_total_pts += cfg.page_tables().unwrap_or(shared_pts / pt_sharer);
                domain_kmem_bytes += cfg.kernel_mem().unwrap_or(def_kmem);
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
                            "Unable to set quota for tile to time={:?}, pts={}",
                            child_total_time,
                            tile_quota.page_tables().total()
                        ),
                    )
                })?;

            // derive a new tile object for the entire domain (so that they cannot change the PMP EPs)
            let domain_pe_usage = if dom.apps().iter().next().unwrap().domains().is_empty() {
                let domain_eps = Some(domain_total_eps);
                let domain_bw = if domain_total_bw > 0 {
                    Some(domain_total_bw)
                }
                else {
                    None
                };
                let domain_time = Some(domain_total_time);
                let domain_pts = Some(domain_total_pts);

                Some(
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
                )
            }
            else {
                None
            };

            for cfg in dom.apps() {
                // determine tile object with potentially reduced number of EPs
                let (domain_tile_usage, child_tile_usage) = if !cfg.domains().is_empty() {
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
                        base.derive(cfg.eps(), cfg.mem_bw.map(|bw| bw.rate), cfg.time(), cfg.page_tables())
                            .map_err(|e| {
                                VerboseError::new(
                                    e.code(),
                                    format!(
                                        "Unable to derive new tile with {:?} EPs, bw={:?}, {:?} time, {:?} pts",
                                        cfg.eps(), cfg.mem_bw, cfg.time(), cfg.page_tables(),
                                    ),
                                )
                            })?,
                    )
                }
                else {
                    // without specified restrictions, childs share their resource quota
                    (None, domain_pe_usage.as_ref().unwrap().clone())
                };

                // mark the tile as used here to prevent that we allocate it again in
                // build_subsystem below.
                res.tiles().add_user(&child_tile_usage);

                // kernel memory for child
                let kmem = if let Some(kmem_bytes) = cfg.kernel_mem() {
                    domain_kmem.derive(kmem_bytes).map_err(|e| {
                        VerboseError::new(
                            e.code(),
                            format!("Unable to derive {}b of kernel memory", kmem_bytes),
                        )
                    })?
                }
                else {
                    domain_kmem.clone()
                };

                // determine user memory for child
                let child_mem = if let Some(umem) = cfg.user_mem() {
                    mem_id += 1;
                    childs::ChildMem::new(mem_id - 1, domain_umem.pool().clone(), umem as GlobOff)
                }
                else {
                    domain_umem.clone()
                };

                // build subsystem if this child contains domains
                let sub = if !cfg.domains().is_empty() {
                    Some(self.build_subsystem(
                        res,
                        cfg,
                        &child_tile_usage,
                        dom,
                        &child_mem,
                        &mem_pool,
                        root,
                    )?)
                }
                else {
                    None
                };

                // create child
                let child_id = childs.alloc_id();
                let mut child = Box::new(childs::OwnChild::new(
                    child_id,
                    tile_usage.clone(),
                    domain_tile_usage,
                    child_tile_usage,
                    // TODO either remove args and daemon from config or remove the clones from OwnChild
                    cfg.args().clone(),
                    cfg.daemon(),
                    kmem,
                    child_mem,
                    cfg.clone(),
                    sub,
                ));
                log!(LogFlags::ResMngChild, "Created {:?}", child);

                // start it immediately if all dependencies are met or remember it for later
                if !child.has_unmet_reqs(res) {
                    starter.start_async(reqs, res, &mut child)?;
                    childs.add(child);
                }
                else {
                    delayed.push(child);
                }
            }
        }
        Ok(delayed)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_subsystem(
        &self,
        res: &mut Resources,
        cfg: &Rc<config::AppConfig>,
        child_tile_usage: &tiles::TileUsage,
        dom: &config::Domain,
        child_mem: &Rc<childs::ChildMem>,
        mem_pool: &Rc<RefCell<memory::MemPool>>,
        root: &config::AppConfig,
    ) -> Result<SubsystemBuilder, VerboseError> {
        // TODO currently, we don't support tile sharing of a resource manager and another
        // activities on the same level. The resource manager needs to set PMP EPs and might
        // thus interfere with the other activities.
        assert!(child_tile_usage.tile_id() != Activity::own().tile_id() && dom.apps().len() == 1);

        let mut sub = SubsystemBuilder::default();

        // add subset of the config for this child as first boot module
        let cfg_range = cfg.cfg_range();
        let cfg_str = &self.cfg_str()[cfg_range.0..cfg_range.1];
        sub.add_config(cfg_str, |size| {
            let cfg_slice = res.memory_mut().alloc_mem(size as GlobOff)?;
            // alloc_mem gives us full pages; cut it down to the string size
            let mgate = cfg_slice.derive_with(0, size)?;
            Ok(mgate)
        })
        .map_err(|e| VerboseError::new(e.code(), "Unable to pass boot.xml to child".to_string()))?;

        // add remaining boot modules
        pass_down_mods(res.mods(), &mut sub, cfg)?;

        // add tiles
        sub.add_tile(child_tile_usage.tile_obj().clone());
        pass_down_tiles(res.tiles(), &mut sub, cfg);

        // serial rgate
        pass_down_serial(&mut sub, cfg);

        // split off the grandchild memories; allocate them from the child quota
        let old_umem_quota = child_mem.quota();
        split_child_mem(cfg, child_mem, sub.tiles.len());
        // determine memory size for the entire subsystem
        let sub_mem = old_umem_quota - child_mem.quota();

        // add memory
        let sub_slice = mem_pool.borrow_mut().allocate_slice(sub_mem).map_err(|e| {
            VerboseError::new(
                e.code(),
                format!("Unable to allocate {}b for subsys", sub_mem),
            )
        })?;
        sub.add_mem(sub_slice.derive()?, sub_slice.in_reserved_mem());

        // add services
        for s in cfg.sess_creators() {
            let (sess_frac, sess_fixed) = split_sessions(root, s.serv_name());
            sub.add_serv(s.serv_name(), sess_frac, sess_fixed, s.sess_count());
        }

        Ok(sub)
    }
}

#[derive(Default)]
pub struct SubsystemBuilder {
    _desc: Option<MemGate>,
    tiles: Vec<Rc<Tile>>,
    mods: Vec<(MemGate, String)>,
    mems: Vec<(MemGate, bool)>,
    servs: Vec<(String, u32, u32, Option<u32>)>,
    serv_objs: Vec<services::Service>,
    serial: bool,
}

impl SubsystemBuilder {
    pub fn add_config<F>(&mut self, cfg: &str, alloc: F) -> Result<(), Error>
    where
        F: FnOnce(usize) -> Result<MemGate, Error>,
    {
        let mut cfg_mem = alloc(cfg.len())?;
        cfg_mem.write(cfg.as_bytes(), 0)?;
        // deactivate the memory gates so that the child can activate them for itself
        cfg_mem.deactivate();

        self.add_mod(cfg_mem, "boot.xml");
        Ok(())
    }

    pub fn add_mod(&mut self, mem: MemGate, name: &str) {
        self.mods.push((mem, name.to_string()));
    }

    pub fn add_tile(&mut self, tile: Rc<Tile>) {
        self.tiles.push(tile);
    }

    pub fn add_mem(&mut self, mem: MemGate, reserved: bool) {
        self.mems.push((mem, reserved));
    }

    pub fn add_serv(&mut self, name: &str, sess_frac: u32, sess_fixed: u32, quota: Option<u32>) {
        if !self.servs.iter().any(|s| s.0 == name) {
            self.servs
                .push((name.to_string(), sess_frac, sess_fixed, quota));
        }
    }

    pub fn add_serial(&mut self) {
        self.serial = true;
    }

    pub fn desc_size(&self) -> usize {
        size_of::<boot::Info>()
            + size_of::<boot::Mod>() * self.mods.len()
            + size_of::<boot::Tile>() * self.tiles.len()
            + size_of::<boot::Mem>() * self.mems.len()
            + size_of::<boot::Service>() * self.servs.len()
    }

    pub fn finalize_async(
        &mut self,
        res: &mut Resources,
        child: childs::Id,
        act: &mut ChildActivity,
    ) -> Result<(), VerboseError> {
        let mut sel = SUBSYS_SELS;
        let mut off: GlobOff = 0;

        let mut mem = res
            .memory_mut()
            .alloc_mem(self.desc_size() as GlobOff)
            .map_err(|e| {
                VerboseError::new(
                    e.code(),
                    format!("Unable to allocate {}b for subsys info", self.desc_size()),
                )
            })?
            .derive()?;

        // boot info
        let info = boot::Info {
            mod_count: self.mods.len() as u64,
            tile_count: self.tiles.len() as u64,
            mem_count: self.mems.len() as u64,
            serv_count: self.servs.len() as u64,
        };
        mem.write_obj(&info, off)?;
        act.delegate_to(CapRngDesc::new(CapType::Object, mem.sel(), 1), sel)?;
        off += size_of::<boot::Info>() as GlobOff;
        sel += 1;

        // serial rgate
        if self.serial {
            act.delegate_to(CapRngDesc::new(CapType::Object, SERIAL_RGATE_SEL, 1), sel)?;
        }
        sel += 1;

        // boot modules
        for (mgate, name) in &self.mods {
            let (addr, size) = mgate.region()?;
            let m = boot::Mod::new(addr, size, name);
            mem.write_obj(&m, off)?;

            act.delegate_to(CapRngDesc::new(CapType::Object, mgate.sel(), 1), sel)?;

            off += size_of::<boot::Mod>() as GlobOff;
            sel += 1;
        }

        // tiles
        for tile in &self.tiles {
            let boot_tile = boot::Tile::new(tile.id(), tile.desc());
            mem.write_obj(&boot_tile, off)?;

            act.delegate_to(CapRngDesc::new(CapType::Object, tile.sel(), 1), sel)?;

            off += size_of::<boot::Tile>() as GlobOff;
            sel += 1;
        }

        // memory regions
        for (mgate, reserved) in &self.mems {
            let (addr, size) = mgate.region()?;
            let boot_mem = boot::Mem::new(addr, size, *reserved);
            mem.write_obj(&boot_mem, off)?;

            act.delegate_to(CapRngDesc::new(CapType::Object, mgate.sel(), 1), sel)?;

            off += size_of::<boot::Mem>() as GlobOff;
            sel += 1;
        }

        // services
        for (name, sess_frac, sess_fixed, sess_quota) in &self.servs {
            let serv = res.services().get_by_name(name).unwrap();
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
            let subserv = serv.derive_async(child, sessions).map_err(|e| {
                VerboseError::new(e.code(), format!("Unable to derive from service {}", name))
            })?;
            let boot_serv = boot::Service::new(name, sessions);
            mem.write_obj(&boot_serv, off)?;

            act.delegate_to(CapRngDesc::new(CapType::Object, subserv.sel(), 1), sel)?;
            act.delegate_to(
                CapRngDesc::new(CapType::Object, subserv.sgate_sel(), 1),
                sel + 1,
            )?;

            off += size_of::<boot::Service>() as GlobOff;
            sel += 2;

            self.serv_objs.push(subserv);
        }

        mem.deactivate();

        self._desc = Some(mem);
        Ok(())
    }
}

#[allow(clippy::vec_box)]
pub(crate) fn start_delayed_async(
    childs: &mut childs::ChildManager,
    delayed: &mut Vec<Box<childs::OwnChild>>,
    reqs: &Requests,
    res: &mut Resources,
    starter: &mut dyn ChildStarter,
) -> Result<(), VerboseError> {
    let mut new_wait = false;
    let mut idx = 0;
    while idx < delayed.len() {
        if delayed[idx].has_unmet_reqs(res) {
            idx += 1;
            continue;
        }

        let mut child = delayed.remove(idx);
        starter.start_async(reqs, res, &mut child)?;
        childs.add(child);
        new_wait = true;
    }

    if new_wait {
        childs.start_waiting(1);
    }
    Ok(())
}

fn pass_down_tiles(
    tiles: &tiles::TileManager,
    sub: &mut SubsystemBuilder,
    app: &config::AppConfig,
) {
    let own_desc = Activity::own().tile_desc();
    let base = TileDesc::new(own_desc.tile_type(), own_desc.isa(), 0);
    for d in app.domains() {
        for child in d.apps() {
            for tile in child.tiles() {
                for _ in 0..tile.count() {
                    if let Ok(usage) = tiles.find_with_attr(base, &tile.tile_type().0) {
                        sub.add_tile(usage.tile_obj().clone());
                        tiles.add_user(&usage);
                    }
                }
            }

            pass_down_tiles(tiles, sub, child);
        }
    }
}

fn pass_down_serial(sub: &mut SubsystemBuilder, app: &config::AppConfig) {
    for d in app.domains() {
        for child in d.apps() {
            if child.can_get_serial() {
                sub.add_serial();
            }
            pass_down_serial(sub, child);
        }
    }
}

fn pass_down_mods(
    mods: &mods::ModManager,
    sub: &mut SubsystemBuilder,
    app: &config::AppConfig,
) -> Result<(), VerboseError> {
    for d in app.domains() {
        for child in d.apps() {
            for m in child.mods() {
                // find mod with desired name
                let bmod = mods.find(m.name().global()).ok_or_else(|| {
                    VerboseError::new(
                        Code::NotFound,
                        format!(
                            "Unable to find boot module {} for subsys",
                            m.name().global()
                        ),
                    )
                })?;

                // derive memory cap with potentially reduced permissions
                let mgate = bmod.memory().derive(0, bmod.size() as usize, m.perm())?;

                sub.add_mod(mgate, bmod.name());
            }

            pass_down_mods(mods, sub, child)?;
        }
    }
    Ok(())
}

fn split_child_mem(cfg: &config::AppConfig, mem: &Rc<childs::ChildMem>, tiles: usize) {
    let mut def_childs = 0;
    for d in cfg.domains() {
        for a in d.apps() {
            if let Some(mut cmem) = a.user_mem() {
                // if the child is a resource manager, it needs some additional memory for that
                // child that isn't passed down to the child
                if !a.domains().is_empty() {
                    cmem += DEF_RESMNG_MEM as usize;
                }
                mem.alloc_mem(cmem as GlobOff);
            }
            else {
                def_childs += 1;
            }
        }
    }

    if def_childs > 0 {
        // The resmng needs some memory for itself (which it will allocate from us later and
        // therefore should stay in the pool). Additionally, for every tile the resmng manages, it
        // potentially needs memory for the multiplexer.
        let remaining = DEF_RESMNG_MEM + (tiles * cfg::FIXED_TILEMUX_MEM) as GlobOff;
        assert!(mem.quota() > remaining);
        // the rest of the quota is split equally among the children
        let per_child = math::round_dn(
            (mem.quota() - remaining) / def_childs,
            cfg::PAGE_SIZE as GlobOff,
        );
        mem.alloc_mem(per_child * def_childs);
    }
}

fn split_mem(res: &Resources, cfg: &config::AppConfig) -> Result<(usize, GlobOff), VerboseError> {
    let mut total_umem = res.memory().capacity();
    let mut total_kmem = Activity::own().kmem().quota()?.total();

    let mut total_kparties = cfg.count_apps() + 1;
    let mut total_mparties = total_kparties;
    for d in cfg.domains() {
        // for every domain we need a multiplexer
        total_umem -= d.mux_mem().unwrap_or(cfg::FIXED_TILEMUX_MEM) as GlobOff;

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
                if total_umem < amem as GlobOff {
                    return Err(VerboseError::new(
                        Code::OutOfMem,
                        format!(
                            "Insufficient user memory (need {}, have {})",
                            amem, total_umem
                        ),
                    ));
                }
                total_umem -= amem as GlobOff;
                total_mparties -= 1;
            }
        }
    }

    let def_kmem = total_kmem / total_kparties;
    let def_umem = math::round_dn(total_umem / total_mparties as GlobOff, PAGE_SIZE as GlobOff);
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
        match cfg.page_tables() {
            Some(n) => {
                assert!(rem_pts >= n);
                rem_pts -= n;
            },
            None => pt_sharer += 1,
        }
    }
    (pt_sharer, rem_pts)
}
