/*
 * Copyright (C) 2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
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

use crate::cap::{CapFlags, Capability, Selector};
use crate::com::MemGate;
use crate::errors::{Code, Error};
use crate::kif::TileDesc;
use crate::quota::Quota;
use crate::rc::Rc;
use crate::syscalls;
use crate::tcu::TileId;
use crate::tiles::Activity;
use crate::time::TimeDuration;

/// Represents a tile in the tiled architecture
///
/// A tile does not only refer to a specific tile on the hardware platform, but also contains a
/// specific resource share. Namely, it provides access to a certain number of endpoints, a certain
/// CPU time (time slice), and certain number of page tables.
///
/// Allocating a new tile yields a [`Tile`] object with all resources of that tile and a so called
/// *root tile capability*. Such capability allows to customize the page-table and CPU time quota as
/// these are not dictated by hardware constraints. Additionally, a root tile capability allows to
/// configure the physical-memory protection endpoints (PMP EPs) that define to which physical
/// memory regions the tile has access.
///
/// New [`Tile`] objects can be *derived* from an existing [`Tile`] object to transfer a subset of
/// the resource share to a new object. Since the creation of child activities (see below) requires
/// a tile capability, different activities on the same tile can be run with different resource
/// shares. Derived objects are no longer root tile capabilities and thus are constrained to the
/// set limits.
///
/// Tile allocations are done via the resource manager and are thus subject to the restrictions set
/// via the boot script.
pub struct Tile {
    cap: Capability,
    id: TileId,
    desc: TileDesc,
    free: bool,
}

/// Contains the different quotas for a tile
#[derive(Default)]
pub struct TileQuota {
    eps: Quota<u32>,
    bw: Quota<u32>,
    time: Quota<TimeDuration>,
    pts: Quota<usize>,
}

impl TileQuota {
    /// Creates a new `TileQuota` object from given quotas.
    pub fn new(
        eps: Quota<u32>,
        bw: Quota<u32>,
        time: Quota<TimeDuration>,
        pts: Quota<usize>,
    ) -> Self {
        Self { eps, bw, time, pts }
    }

    /// Returns the endpoint quota
    pub fn endpoints(&self) -> &Quota<u32> {
        &self.eps
    }

    /// Returns the memory-bandwidth quota (in bytes/millisecond)
    pub fn mem_bw(&self) -> &Quota<u32> {
        &self.bw
    }

    /// Returns the time quota
    pub fn time(&self) -> &Quota<TimeDuration> {
        &self.time
    }

    /// Returns the page-table quota
    pub fn page_tables(&self) -> &Quota<usize> {
        &self.pts
    }
}

impl fmt::Debug for TileQuota {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "TileQuota[eps={:?}, bw={:?}b/ms, time={:?}ns, pts={:?}]",
            self.endpoints(),
            self.mem_bw(),
            self.time(),
            self.page_tables()
        )
    }
}

/// Additional arguments for the allocation of tiles
#[derive(Copy, Clone)]
pub struct TileArgs {
    init: bool,
}

impl Default for TileArgs {
    fn default() -> Self {
        Self { init: true }
    }
}

impl TileArgs {
    /// Sets whether the tile should be initialized with TileMux and PMP EPs should be inherited
    /// from our tile
    pub fn init(mut self, init: bool) -> Self {
        self.init = init;
        self
    }
}

impl Tile {
    /// Allocates a new tile from the resource manager with given description
    pub fn new(desc: TileDesc) -> Result<Rc<Self>, Error> {
        Self::new_with(desc, TileArgs::default())
    }

    /// Allocates a new tile from the resource manager with given description
    pub fn new_with(desc: TileDesc, args: TileArgs) -> Result<Rc<Self>, Error> {
        let sel = Activity::own().alloc_sel();
        let (id, ndesc) = Activity::own()
            .resmng()
            .unwrap()
            .alloc_tile(sel, desc, args.init)?;
        Ok(Rc::new(Tile {
            cap: Capability::new(sel, CapFlags::KEEP_CAP),
            id,
            desc: ndesc,
            free: true,
        }))
    }

    /// Binds a new tile object to given selector
    pub fn new_bind(id: TileId, desc: TileDesc, sel: Selector) -> Self {
        Tile {
            cap: Capability::new(sel, CapFlags::KEEP_CAP),
            id,
            desc,
            free: false,
        }
    }

    /// Gets a tile with given description.
    ///
    /// The description is an '|' separated list of properties that will be tried in order. Two
    /// special properties are supported:
    /// - "own" to denote the own tile (provided that it has support for multiple activities)
    /// - "clone" to denote a separate tile that is identical to the own tile
    /// - "compat" to denote a separate tile that is compatible to the own tile (same ISA and type)
    ///
    /// For other properties, see [`TileDesc::with_properties`].
    ///
    /// Examples:
    /// - tile with an arbitrary ISA, but preferred the own: "own|core"
    /// - Identical tile, but preferred a separate one: "clone|own"
    /// - BOOM core if available, otherwise any core: "boom|core"
    /// - BOOM with NIC if available, otherwise a Rocket: "boom+nic|rocket"
    pub fn get(desc: &str) -> Result<Rc<Self>, Error> {
        Self::get_with(desc, TileArgs::default())
    }

    /// Gets a tile with given description and custom arguments.
    pub fn get_with(desc: &str, args: TileArgs) -> Result<Rc<Self>, Error> {
        let own = Activity::own().tile();
        for props in desc.split('|') {
            match props {
                "own" => {
                    if own.desc().supports_tilemux() && own.desc().has_virtmem() {
                        return Ok(own.clone());
                    }
                },
                "clone" => {
                    if let Ok(tile) = Self::new_with(own.desc(), args) {
                        return Ok(tile);
                    }
                },
                "compat" => {
                    let type_isa = TileDesc::new(own.desc().tile_type(), own.desc().isa(), 0);
                    if let Ok(tile) = Self::new_with(type_isa, args) {
                        return Ok(tile);
                    }
                },
                p => {
                    let base = TileDesc::new(own.desc().tile_type(), own.desc().isa(), 0);
                    if let Ok(tile) = Self::new_with(base.with_properties(p), args) {
                        return Ok(tile);
                    }
                },
            }
        }
        Err(Error::new(Code::NotFound))
    }

    /// Derives a new tile object from `self` with a subset of the resources, removing them from
    /// `self`
    ///
    /// The four resources are the number of EPs, the memory bandwidth in bytes/millisecond, the
    /// time slice length in nanoseconds, and the number of page tables.
    pub fn derive(
        &self,
        eps: Option<u32>,
        bw: Option<u32>,
        time: Option<TimeDuration>,
        pts: Option<usize>,
    ) -> Result<Rc<Self>, Error> {
        let sel = Activity::own().alloc_sel();
        syscalls::derive_tile(self.sel(), sel, eps, bw, time, pts)?;
        Ok(Rc::new(Tile {
            cap: Capability::new(sel, CapFlags::empty()),
            desc: self.desc(),
            id: self.id(),
            free: false,
        }))
    }

    /// Returns the selector
    pub fn sel(&self) -> Selector {
        self.cap.sel()
    }

    /// Returns the tile id
    pub fn id(&self) -> TileId {
        self.id
    }

    /// Returns the tile description
    pub fn desc(&self) -> TileDesc {
        self.desc
    }

    /// Returns the EP, time, and page table quota
    pub fn quota(&self) -> Result<TileQuota, Error> {
        syscalls::tile_quota(self.sel())
    }

    /// Sets the quota of the tile with given selector to specified initial values (given time slice
    /// length, bytes per millisecond memory bandwidth, and number of page tables).
    ///
    /// This call requires a root tile capability.
    pub fn set_quota(&self, bw: u32, time: TimeDuration, pts: usize) -> Result<(), Error> {
        syscalls::tile_set_quota(self.sel(), bw, time, pts)
    }

    /// Creates a [`MemGate`] for the internal memory of this tile
    ///
    /// The tile needs to have internal memory (see [`TileDesc::has_memory`]).
    ///
    /// This call requires a non-derived tile capability.
    pub fn memory(&self) -> Result<MemGate, Error> {
        if self.desc.has_memory() {
            let sel = Activity::own().alloc_sel();
            syscalls::tile_mem(sel, self.sel())?;
            Ok(MemGate::new_owned_bind(sel))
        }
        else {
            Err(Error::new(Code::InvArgs))
        }
    }
}

impl Drop for Tile {
    fn drop(&mut self) {
        if self.free {
            Activity::own().resmng().unwrap().free_tile(self.sel()).ok();
        }
    }
}

impl fmt::Debug for Tile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}[sel: {}, desc: {:?}]",
            self.id(),
            self.sel(),
            self.desc()
        )
    }
}
