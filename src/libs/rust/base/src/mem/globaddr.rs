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
use core::ops;

use crate::errors::{Code, Error};
use crate::io::LogFlags;
use crate::kif::TileDesc;
use crate::kif::{PageFlags, Perm};
use crate::mem::{PhysAddr, PhysAddrRaw};
use crate::serialize::{Deserialize, Serialize};
use crate::tcu::{EpId, TileId, PMEM_PROT_EPS, TCU};

/// The underlying type for [`GlobAddr`]
pub type GlobAddrRaw = u64;

/// The offset in a [`GlobAddr`]
pub type GlobOff = u64;

/// Represents a global address
///
/// A global address is a combination of a tile id and an offset within the tile. On memory tiles,
/// the offset is simply the offset within the memory inside the tile. On compute tiles, the offset
/// is a [`PhysAddr`] that will be translated through PMP to a global address on a memory tile.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct GlobAddr {
    val: GlobAddrRaw,
}

const TILE_SHIFT: GlobAddrRaw = 49;
const TILE_OFFSET: GlobAddrRaw = 0x4000;

impl GlobAddr {
    /// Creates a new global address from the given raw value
    pub fn new(addr: GlobAddrRaw) -> GlobAddr {
        GlobAddr { val: addr }
    }

    /// Creates a new global address from the given tile id and offset
    pub fn new_with(tile: TileId, off: GlobOff) -> GlobAddr {
        Self::new(((TILE_OFFSET + tile.raw() as GlobAddrRaw) << TILE_SHIFT) | off)
    }

    /// Creates a new global address from the given physical address
    ///
    /// The function assumes that the given physical address is accessible through a PMP EP and uses
    /// the current configuration of this PMP EP to translate the physical address into a global
    /// address.
    pub fn new_from_phys(phys: PhysAddr) -> Result<GlobAddr, Error> {
        let epid = phys.ep();
        let off = phys.offset();

        let res = TCU::unpack_mem_ep(epid)
            .map(|(tile, addr, _, _)| GlobAddr::new_with(tile, addr + off as GlobOff))
            .ok_or_else(|| Error::new(Code::InvArgs));
        log!(LogFlags::LibXlate, "Translated {} to {}", phys, 0);
        res
    }

    /// Returns the raw value
    pub fn raw(self) -> GlobAddrRaw {
        self.val
    }

    /// Returns whether a tile id is set
    pub fn has_tile(self) -> bool {
        self.val >= (TILE_OFFSET << TILE_SHIFT)
    }

    /// Returns the tile id
    pub fn tile(self) -> TileId {
        TileId::new_from_raw(((self.val >> TILE_SHIFT) - TILE_OFFSET) as u16)
    }

    /// Returns the offset
    pub fn offset(self) -> GlobOff {
        (self.val & ((1 << TILE_SHIFT) - 1)) as GlobOff
    }

    /// Translates this global address to a physical address based on the PMP EPs.
    ///
    /// The function assumes that the callers tile has a physical-memory protection (PMP) endpoint
    /// (EP) that allows the caller to access this memory. Therefore, it walks over all PMP EPs to
    /// check which EP provides access to the address and translates it into the corresponding
    /// physical address.
    pub fn to_phys(self, tile_desc: TileDesc, access: PageFlags) -> Result<PhysAddr, Error> {
        self.to_phys_with(tile_desc, access, crate::tcu::TCU::unpack_mem_ep)
    }

    /// Translates this global address to a physical address based on the given function to retrieve
    /// a PMP EP.
    ///
    /// Similarly to `to_phys`, `to_phys_with` translates from this global address to the physical
    /// address, but instead of reading the PMP EPs, it calls `get_ep` for every EP id.
    pub fn to_phys_with<F>(
        self,
        tile_desc: TileDesc,
        access: PageFlags,
        get_ep: F,
    ) -> Result<PhysAddr, Error>
    where
        F: Fn(EpId) -> Option<(TileId, GlobOff, GlobOff, Perm)>,
    {
        if !self.has_tile() {
            return Ok(PhysAddr::new_raw(tile_desc, self.raw() as PhysAddrRaw));
        }

        // find memory EP that contains the address
        for ep in 0..PMEM_PROT_EPS as EpId {
            if let Some((tile, addr, size, perm)) = get_ep(ep) {
                log!(
                    LogFlags::LibXlate,
                    "Translating {}: considering EP{} with tile={}, addr={:#x}, size={:#x}",
                    self,
                    ep,
                    tile,
                    addr,
                    size
                );

                // does the EP contain this address?
                if self.tile() == tile && self.offset() >= addr && self.offset() < addr + size {
                    let flags = PageFlags::from(perm);

                    // check access permissions
                    if access.contains(PageFlags::R) && !flags.contains(PageFlags::R) {
                        return Err(Error::new(Code::NoPerm));
                    }
                    if access.contains(PageFlags::W) && !flags.contains(PageFlags::W) {
                        return Err(Error::new(Code::NoPerm));
                    }

                    let phys = PhysAddr::new(tile_desc, ep, (self.offset() - addr) as PhysAddrRaw);
                    log!(LogFlags::LibXlate, "Translated {} to {}", self, phys);
                    return Ok(phys);
                }
            }
        }
        Err(Error::new(Code::InvArgs))
    }
}

impl fmt::Display for GlobAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.has_tile() {
            write!(f, "G[{}+{:#x}]", self.tile(), self.offset())
        }
        // we need global addresses without tile prefix for, e.g., the TCU MMIO region
        else {
            write!(f, "G[{:#x}]", self.raw())
        }
    }
}

impl fmt::Debug for GlobAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (self as &dyn fmt::Display).fmt(f)
    }
}

impl ops::Add<GlobOff> for GlobAddr {
    type Output = GlobAddr;

    fn add(self, rhs: GlobOff) -> Self::Output {
        GlobAddr::new(self.val + rhs)
    }
}
