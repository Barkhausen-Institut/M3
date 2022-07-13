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

use m3::cell::{Cell, LazyReadOnlyCell, RefCell};
use m3::col::Vec;
use m3::com::MemGate;
use m3::errors::{Code, Error};
use m3::kif::{Perm, TileDesc};
use m3::log;
use m3::rc::Rc;
use m3::syscalls;
use m3::tcu::{EpId, TileId, PMEM_PROT_EPS, TCU};
use m3::tiles::{Activity, Tile};

struct ManagedTile {
    id: TileId,
    tile: Rc<Tile>,
    users: Cell<u32>,
}

impl ManagedTile {
    fn add_user(&self) {
        self.users.set(self.users.get() + 1);
    }

    fn remove_user(&self) -> u32 {
        self.users.replace(self.users.get() - 1)
    }
}

struct PMP {
    next_ep: EpId,
    regions: Vec<(MemGate, usize)>,
}

impl PMP {
    fn new() -> Self {
        Self {
            // PMP EPs start at 1, because 0 is reserved for TileMux
            next_ep: 1,
            regions: Vec::new(),
        }
    }
}

pub struct TileUsage {
    idx: Option<usize>,
    pmp: Rc<RefCell<PMP>>,
    tile: Rc<Tile>,
}

impl TileUsage {
    fn new(idx: usize) -> Self {
        Self {
            idx: Some(idx),
            pmp: Rc::new(RefCell::new(PMP::new())),
            tile: get().get(idx),
        }
    }

    pub fn new_obj(tile: Rc<Tile>) -> Self {
        Self {
            idx: None,
            pmp: Rc::new(RefCell::new(PMP::new())),
            tile,
        }
    }

    pub fn tile_id(&self) -> TileId {
        self.tile.id()
    }

    pub fn tile_obj(&self) -> &Rc<Tile> {
        &self.tile
    }

    pub fn add_mem_region(&self, mgate: MemGate, size: usize, set: bool) -> Result<(), Error> {
        let mut pmp = self.pmp.borrow_mut();
        if set {
            syscalls::set_pmp(self.tile_obj().sel(), mgate.sel(), pmp.next_ep)?;
            pmp.next_ep += 1;
        }
        pmp.regions.push((mgate, size));
        Ok(())
    }

    pub fn inherit_mem_regions(&self, tile: &Rc<TileUsage>) -> Result<(), Error> {
        let pmps = tile.pmp.borrow();
        for (mgate, size) in pmps.regions.iter() {
            self.add_mem_region(mgate.derive(0, *size, Perm::RWX)?, *size, true)?;
        }
        Ok(())
    }

    pub fn derive(
        &self,
        eps: Option<u32>,
        bw: Option<u32>,
        time: Option<u64>,
        pts: Option<usize>,
    ) -> Result<TileUsage, Error> {
        let tile = self.tile_obj().derive(eps, bw, time, pts)?;
        if let Some(idx) = self.idx {
            get().tiles[idx].add_user();
        }
        let _quota = tile.quota().unwrap();
        log!(
            crate::LOG_TILES,
            "Deriving Tile{}: (eps={}, bw={}, time={}, pts={})",
            self.tile_id(),
            _quota.mem_bw(),
            _quota.endpoints(),
            _quota.time(),
            _quota.page_tables(),
        );
        Ok(TileUsage {
            idx: self.idx,
            pmp: self.pmp.clone(),
            tile,
        })
    }
}

impl Drop for TileUsage {
    fn drop(&mut self) {
        if let Some(idx) = self.idx {
            get().free(idx);
        }
    }
}

pub struct TileManager {
    tiles: Vec<ManagedTile>,
}

static MNG: LazyReadOnlyCell<TileManager> = LazyReadOnlyCell::default();

pub fn create(tiles: Vec<(TileId, Rc<Tile>)>) {
    let mut mng = TileManager {
        tiles: Vec::with_capacity(tiles.len()),
    };
    for (id, tile) in tiles {
        mng.tiles.push(ManagedTile {
            id,
            tile,
            users: Cell::from(0),
        });
    }
    MNG.set(mng);
}

pub fn get() -> &'static TileManager {
    MNG.get()
}

impl TileManager {
    pub const fn new() -> Self {
        TileManager { tiles: Vec::new() }
    }

    pub fn count(&self) -> usize {
        self.tiles.len()
    }

    pub fn id(&self, idx: usize) -> TileId {
        self.tiles[idx].id
    }

    pub fn get(&self, idx: usize) -> Rc<Tile> {
        self.tiles[idx].tile.clone()
    }

    pub fn find_with_desc(&self, desc: &str) -> Option<usize> {
        let own = Activity::own().tile().desc();
        for props in desc.split('|') {
            let base = TileDesc::new(own.tile_type(), own.isa(), 0);
            if let Ok(idx) = self.find(base.with_properties(props)) {
                return Some(idx);
            }
        }
        log!(crate::LOG_TILES, "Unable to find tile with desc {}", desc);
        None
    }

    pub fn find_and_alloc_with_desc(&self, desc: &str) -> Result<TileUsage, Error> {
        let own = Activity::own().tile().desc();
        for props in desc.split('|') {
            let base = TileDesc::new(own.tile_type(), own.isa(), 0);
            if let Ok(tile) = self.find_and_alloc(base.with_properties(props)) {
                return Ok(tile);
            }
        }
        log!(crate::LOG_TILES, "Unable to find tile with desc {}", desc);
        Err(Error::new(Code::NotFound))
    }

    pub fn find_and_alloc(&self, desc: TileDesc) -> Result<TileUsage, Error> {
        self.find(desc).map(|idx| {
            let usage = TileUsage::new(idx);
            if self.tiles[idx].id == Activity::own().tile_id() {
                // if it's our own tile, set it to the first free PMP EP
                let mut pmp = usage.pmp.borrow_mut();
                for ep in pmp.next_ep..PMEM_PROT_EPS as EpId {
                    if !TCU::is_valid(ep) {
                        break;
                    }
                    pmp.next_ep += 1;
                }
            }
            self.alloc(idx);
            usage
        })
    }

    fn find(&self, desc: TileDesc) -> Result<usize, Error> {
        for (id, tile) in self.tiles.iter().enumerate() {
            if tile.users.get() == 0
                && tile.tile.desc().isa() == desc.isa()
                && tile.tile.desc().tile_type() == desc.tile_type()
                && (desc.attr().is_empty() || tile.tile.desc().attr() == desc.attr())
            {
                return Ok(id);
            }
        }
        Err(Error::new(Code::NotFound))
    }

    pub fn alloc(&self, idx: usize) {
        log!(
            crate::LOG_TILES,
            "Allocating tile{}: {:?} (eps={})",
            self.tiles[idx].id,
            self.tiles[idx].tile.desc(),
            self.get(idx).quota().unwrap().endpoints(),
        );
        self.tiles[idx].add_user();
    }

    fn free(&self, idx: usize) {
        let tile = &self.tiles[idx];
        if tile.remove_user() == 1 {
            log!(
                crate::LOG_TILES,
                "Freeing tile{}: {:?}",
                tile.id,
                tile.tile.desc()
            );
        }
    }
}
