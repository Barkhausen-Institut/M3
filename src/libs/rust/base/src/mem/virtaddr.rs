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

use crate::impl_prim_int;
use crate::kif::TileDesc;
use crate::mem::{GlobOff, PhysAddr, PhysAddrRaw};
use crate::serialize::{Deserialize, Serialize};

/// The underlying type for [`VirtAddr`]
pub type VirtAddrRaw = u64;

/// Represents a virtual address
///
/// Like on most systems, virtual addresses are translated via page tables to a physical address
/// ([`PhysAddr`]). [`VirtAddr`] implements [`num_traits::PrimInt`] and therefore supports the usual
/// arithmetic and bitwise operators. Additionally, conversions between pointers, `usize`, `goff`
/// and [`VirtAddr`] are supported.
#[derive(Default, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VirtAddr(VirtAddrRaw);

impl VirtAddr {
    /// Creates a null pointer
    pub const fn null() -> Self {
        Self(0)
    }

    /// Creates a virtual address from given raw address
    pub const fn new(addr: VirtAddrRaw) -> Self {
        Self(addr)
    }

    /// Returns the underlying raw address
    pub const fn as_raw(&self) -> VirtAddrRaw {
        self.0
    }

    /// Returns this address as an immutable pointer to `T`
    pub const fn as_ptr<T>(&self) -> *const T {
        self.0 as *const T
    }

    /// Returns this address as an mutable pointer to `T`
    pub const fn as_mut_ptr<T>(&self) -> *mut T {
        self.0 as *mut T
    }

    /// Returns this address as a global offset
    pub const fn as_goff(&self) -> GlobOff {
        self.0 as GlobOff
    }

    /// Returns this address as a [`PhysAddr`] and therefore assumes an identity mapping
    pub const fn as_phys(&self, tile_desc: TileDesc) -> PhysAddr {
        PhysAddr::new_raw(tile_desc, self.0 as PhysAddrRaw)
    }

    /// Returns this address as a locally valid virtual address (`usize`)
    pub const fn as_local(&self) -> usize {
        self.0 as usize
    }

    /// Returns true if this is a null pointer
    pub const fn is_null(&self) -> bool {
        self.0 == 0
    }
}

impl From<usize> for VirtAddr {
    fn from(addr: usize) -> Self {
        Self(addr as VirtAddrRaw)
    }
}

impl<T> From<*const T> for VirtAddr {
    fn from(addr: *const T) -> Self {
        Self(addr as VirtAddrRaw)
    }
}

impl<T> From<*mut T> for VirtAddr {
    fn from(addr: *mut T) -> Self {
        Self(addr as VirtAddrRaw)
    }
}

impl fmt::Display for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "V[{:#x}]", self.0)
    }
}

impl fmt::Debug for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "V[{:#x}]", self.0)
    }
}

impl ops::Add<usize> for VirtAddr {
    type Output = Self;

    fn add(self, rhs: usize) -> Self::Output {
        Self(self.0 + (rhs as VirtAddrRaw))
    }
}

impl ops::Add<GlobOff> for VirtAddr {
    type Output = Self;

    fn add(self, rhs: GlobOff) -> Self::Output {
        Self(self.0 + (rhs as VirtAddrRaw))
    }
}

impl ops::AddAssign<usize> for VirtAddr {
    fn add_assign(&mut self, rhs: usize) {
        self.0 += rhs as VirtAddrRaw;
    }
}

impl ops::Sub<usize> for VirtAddr {
    type Output = Self;

    fn sub(self, rhs: usize) -> Self::Output {
        Self(self.0 - (rhs as VirtAddrRaw))
    }
}

impl_prim_int!(VirtAddr, VirtAddrRaw);
