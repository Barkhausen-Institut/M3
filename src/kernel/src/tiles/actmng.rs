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

use base::cell::LazyStaticRefCell;
use base::cfg;
use base::col::Vec;
use base::errors::{Code, Error};
use base::goff;
use base::kif;
use base::math;
use base::mem::GlobAddr;
use base::rc::{Rc, SRc};
use base::tcu;
use base::vec;

use crate::args;
use crate::cap::{Capability, KMemObject, KObject, MGateObject, RGateObject, TileObject};
use crate::ktcu;
use crate::mem::{self, Allocation};
use crate::platform;
use crate::tiles::{tilemng, Activity, ActivityFlags, State, TileMux};

pub struct ActivityMng {
    acts: Vec<Option<Rc<Activity>>>,
    count: usize,
    next_id: tcu::ActId,
}

static INST: LazyStaticRefCell<ActivityMng> = LazyStaticRefCell::default();

pub fn init() {
    INST.set(ActivityMng {
        acts: vec![None; cfg::MAX_ACTS],
        count: 0,
        next_id: 0,
    });
}

pub fn deinit() {
    INST.unset();
}

impl ActivityMng {
    pub fn count() -> usize {
        INST.borrow().count
    }

    pub fn activity(id: tcu::ActId) -> Option<Rc<Activity>> {
        INST.borrow().acts[id as usize].as_ref().cloned()
    }

    fn get_id() -> Result<tcu::ActId, Error> {
        let mut actmng = INST.borrow_mut();
        for id in actmng.next_id..cfg::MAX_ACTS as tcu::ActId {
            if actmng.acts[id as usize].is_none() {
                actmng.next_id = id + 1;
                return Ok(id);
            }
        }

        for id in 0..actmng.next_id {
            if actmng.acts[id as usize].is_none() {
                actmng.next_id = id + 1;
                return Ok(id);
            }
        }

        Err(Error::new(Code::NoSpace))
    }

    pub fn create_activity_async(
        name: &str,
        tile: SRc<TileObject>,
        eps_start: tcu::EpId,
        kmem: SRc<KMemObject>,
        flags: ActivityFlags,
    ) -> Result<Rc<Activity>, Error> {
        let id: tcu::ActId = Self::get_id()?;
        let tile_id = tile.tile();

        let act = Activity::new(name, id, tile, eps_start, kmem, flags)?;

        klog!(
            ACTIVITIES,
            "Created Activity {} [id={}, tile={}]",
            name,
            id,
            tile_id
        );

        let clone = act.clone();
        {
            let mut actmng = INST.borrow_mut();
            actmng.acts[id as usize] = Some(act);
            actmng.count += 1;
        }

        tilemng::tilemux(tile_id).add_activity(id);
        if flags.is_empty() {
            Self::init_activity_async(&clone).unwrap();
        }

        Ok(clone)
    }

    fn init_activity_async(act: &Activity) -> Result<(), Error> {
        if platform::tile_desc(act.tile_id()).supports_tilemux() {
            TileMux::activity_init_async(
                tilemng::tilemux(act.tile_id()),
                act.id(),
                act.tile().time_quota_id(),
                act.tile().pt_quota_id(),
                act.eps_start(),
            )?;
        }

        act.init_async()
    }

    pub fn start_activity_async(act: &Activity) -> Result<(), Error> {
        if platform::tile_desc(act.tile_id()).supports_tilemux() {
            TileMux::activity_ctrl_async(
                tilemng::tilemux(act.tile_id()),
                act.id(),
                kif::tilemux::ActivityOp::START,
            )
        }
        else {
            Ok(())
        }
    }

    pub fn stop_activity_async(act: &Activity, stop: bool, reset: bool) -> Result<(), Error> {
        if stop && platform::tile_desc(act.tile_id()).supports_tilemux() {
            TileMux::activity_ctrl_async(
                tilemng::tilemux(act.tile_id()),
                act.id(),
                kif::tilemux::ActivityOp::STOP,
            )?;
        }

        if reset && !platform::tile_desc(act.tile_id()).is_programmable() {
            ktcu::reset_tile(act.tile_id(), act.pid().unwrap_or(0))
        }
        else {
            Ok(())
        }
    }

    pub fn start_root_async() -> Result<(), Error> {
        // TODO temporary
        let isa = platform::tile_desc(platform::kernel_tile()).isa();
        let tile_emem = kif::TileDesc::new(kif::TileType::COMP_EMEM, isa, 0);
        let tile_imem = kif::TileDesc::new(kif::TileType::COMP_IMEM, isa, 0);

        let tile_id = tilemng::find_tile(&tile_emem)
            .unwrap_or_else(|| tilemng::find_tile(&tile_imem).unwrap());
        let tile = tilemng::tilemux(tile_id).tile().clone();

        let kmem = KMemObject::new(args::get().kmem - cfg::FIXED_KMEM);
        let act = Self::create_activity_async(
            "root",
            tile,
            tcu::FIRST_USER_EP,
            kmem,
            ActivityFlags::IS_ROOT,
        )
        .expect("Unable to create Activity for root");

        let mut sel = kif::FIRST_FREE_SEL;

        // boot info
        {
            let alloc = Allocation::new(platform::info_addr(), platform::info_size() as goff);
            let cap = Capability::new(
                sel,
                KObject::MGate(MGateObject::new(alloc, kif::Perm::RWX, false)),
            );

            act.obj_caps().borrow_mut().insert(cap).unwrap();
            sel += 1;
        }

        // serial rgate
        {
            let cap = Capability::new(
                sel,
                KObject::RGate(RGateObject::new(
                    cfg::SERIAL_BUF_ORD,
                    cfg::SERIAL_BUF_ORD,
                    true,
                )),
            );
            act.obj_caps().borrow_mut().insert(cap).unwrap();
            sel += 1;
        }

        // boot modules
        for m in platform::mods() {
            let size = math::round_up(m.size as usize, cfg::PAGE_SIZE);
            let alloc = Allocation::new(GlobAddr::new(m.addr), size as goff);
            let cap = Capability::new(
                sel,
                KObject::MGate(MGateObject::new(alloc, kif::Perm::RWX, false)),
            );

            act.obj_caps().borrow_mut().insert(cap).unwrap();
            sel += 1;
        }

        // TILES
        for tile in platform::user_tiles() {
            let tile_obj = tilemng::tilemux(tile).tile().clone();
            let cap = Capability::new(sel, KObject::Tile(tile_obj));
            act.obj_caps().borrow_mut().insert(cap).unwrap();
            sel += 1;
        }

        // memory
        #[cfg(not(target_vendor = "host"))]
        let mut mem_ep = 1;

        for m in mem::borrow_mut().mods() {
            if m.mem_type() != mem::MemType::KERNEL {
                let alloc = Allocation::new(m.addr(), m.capacity());
                // create a derive MGateObject to prevent freeing the memory if it's of type ROOT
                let mgate_obj = MGateObject::new(alloc, kif::Perm::RWX, true);

                #[cfg(not(target_vendor = "host"))]
                {
                    // we currently assume that we have enough protection EPs for all user memory regions
                    assert!(mem_ep < tcu::PMEM_PROT_EPS as tcu::EpId);

                    // configure physical memory protection EP
                    tilemng::tilemux(tile_id)
                        .config_mem_ep(
                            mem_ep,
                            kif::tilemux::ACT_ID as tcu::ActId,
                            &mgate_obj,
                            m.addr().tile(),
                        )
                        .unwrap();
                    mem_ep += 1;
                }

                if m.mem_type() != mem::MemType::ROOT {
                    // insert capability
                    let cap = Capability::new(sel, KObject::MGate(mgate_obj));
                    act.obj_caps().borrow_mut().insert(cap).unwrap();
                    sel += 1;
                }
            }
        }

        // let root know the first usable selector
        act.set_first_sel(sel);

        // go!
        Self::init_activity_async(&act)?;
        act.start_app_async(None)
    }

    pub fn start_linux_async() -> Result<Rc<Activity>, Error> {
        // create dummy activity on tile 1
        let tile = tilemng::tilemux(1).tile().clone();
        let kmem = KMemObject::new(args::get().kmem - cfg::FIXED_KMEM);
        let act = Self::create_activity_async(
            "linux",
            tile,
            tcu::FIRST_USER_EP,
            kmem,
            ActivityFlags::IS_LINUX,
        )
        .expect("Unable to create Activity for linux");

        // TODO: actually start linux from here

        Ok(act)
    }

    pub fn remove_activity_async(id: tcu::ActId) {
        let mut actmng = INST.borrow_mut();
        // Replace item at position
        // https://stackoverflow.com/questions/33204273/how-can-i-take-ownership-of-a-vec-element-and-replace-it-with-something-else
        let act: Option<Rc<Activity>> = base::mem::replace(&mut actmng.acts[id as usize], None);

        match act {
            Some(ref v) => {
                actmng.count -= 1;
                drop(actmng);
                tilemng::tilemux(v.tile_id()).rem_activity(v.id());
                v.force_stop_async(v.state() != State::DEAD);
            },
            None => panic!("Removing nonexisting Activity with id {}", id),
        };
    }

    #[cfg(target_vendor = "host")]
    pub fn find_activity<P>(pred: P) -> Option<Rc<Activity>>
    where
        P: Fn(&Rc<Activity>) -> bool,
    {
        let actmng = INST.borrow();
        for v in &actmng.acts {
            if let Some(act) = v.as_ref() {
                if pred(act) {
                    return Some(act.clone());
                }
            }
        }
        None
    }
}

impl Drop for ActivityMng {
    fn drop(&mut self) {
        for _act in self.acts.drain(0..).flatten() {
            #[cfg(target_vendor = "host")]
            if let Some(pid) = _act.pid() {
                crate::arch::childs::kill_child(pid);
            }
        }
    }
}
