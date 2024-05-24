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

use core::fmt;
use core::ops;

use crate::kif::TileDesc;
use crate::mem::GlobOff;
use crate::serialize::{Deserialize, Serialize};
use crate::tcu::EpId;

/// The underlying type for [`PhysAddr`]
pub type PhysAddrRaw = u32;

/// Represents a physical address
///
/// Physical addresses are used locally on a tile and need to first go through the TCU's physical
/// memory protection (PMP) to obtain the final address in memory. For that reason, physical
/// addresses consist of an endpoint id and an offset to refer to a specific offset in a memory
/// region accessed via a specific PMP endpoint.
#[derive(Default, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PhysAddr {
    tile_desc: TileDesc,
    raw: PhysAddrRaw,
}

impl PhysAddr {
    /// Creates a new physical address for given endpoint and offset
    pub fn new(tile_desc: TileDesc, ep: EpId, off: PhysAddrRaw) -> Self {
        Self {
            tile_desc,
            raw: (ep as PhysAddrRaw) << 30 | ((tile_desc.mem_offset() as PhysAddrRaw) + off),
        }
    }

    /// Creates a new physical address from given raw address
    pub const fn new_raw(tile_desc: TileDesc, addr: PhysAddrRaw) -> Self {
        Self {
            tile_desc,
            raw: addr,
        }
    }

    /// Returns the underlying raw address
    pub fn as_raw(&self) -> PhysAddrRaw {
        self.raw
    }

    /// Returns this address as a global offset
    pub fn as_goff(&self) -> GlobOff {
        self.raw as GlobOff
    }

    /// Returns the endpoint of this physical address
    pub fn ep(&self) -> EpId {
        ((self.raw - self.tile_desc.mem_offset() as PhysAddrRaw) >> 30) as EpId
    }

    /// Returns the offset of this physical address
    pub fn offset(&self) -> PhysAddrRaw {
        (self.raw - self.tile_desc.mem_offset() as PhysAddrRaw) & 0x3FFF_FFFF
    }
}

impl fmt::Display for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "P[EP{}+{:#x}]", self.ep(), self.offset())
    }
}

impl fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "P[EP{}+{:#x}]", self.ep(), self.offset())
    }
}

impl ops::Add<PhysAddrRaw> for PhysAddr {
    type Output = Self;

    fn add(self, rhs: PhysAddrRaw) -> Self::Output {
        Self {
            tile_desc: self.tile_desc,
            raw: self.raw + (rhs as PhysAddrRaw),
        }
    }
}

impl ops::AddAssign<PhysAddrRaw> for PhysAddr {
    fn add_assign(&mut self, rhs: PhysAddrRaw) {
        self.raw += rhs as PhysAddrRaw;
    }
}
