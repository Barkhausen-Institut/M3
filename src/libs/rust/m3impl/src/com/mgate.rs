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

use base::mem::GlobAddr;

use crate::cap::{CapFlags, Capability, SelSpace, Selector};
use crate::col::Vec;
use crate::com::ep::EP;
use crate::com::gate::Gate;
use crate::com::GateCap;
use crate::errors::Error;
use crate::kif::INVALID_SEL;
use crate::mem::{GlobOff, VirtAddr};
use crate::syscalls;
use crate::tcu;
use crate::tiles::Activity;

pub use crate::kif::Perm;

/// A memory capability is the precursor of a `MemGate`
///
/// `MemCap` implements `GateCap` and can therefore be turned into a `MemGate` through activation.
#[derive(Debug)]
pub struct MemCap {
    cap: Capability,
    resmng: bool,
}

impl MemCap {
    /// Creates a new `MemCap` that has access to a region of `size` bytes with permissions `perm`.
    ///
    /// This method will allocate `size` bytes with given permissions from the resource manager.
    pub fn new(size: GlobOff, perm: Perm) -> Result<Self, Error> {
        Self::new_with(MGateArgs::new(size, perm))
    }

    /// Creates a new `MemCap` with given arguments.
    ///
    /// This method will allocate `size` bytes with given permissions from the resource manager.
    pub fn new_with(args: MGateArgs) -> Result<Self, Error> {
        let sel = if args.sel == INVALID_SEL {
            SelSpace::get().alloc_sel()
        }
        else {
            args.sel
        };

        Activity::own()
            .resmng()
            .unwrap()
            .alloc_mem(sel, args.size as GlobOff, args.perm)?;
        Ok(Self {
            cap: Capability::new(sel, CapFlags::empty()),
            resmng: true,
        })
    }

    /// Creates a new `MemCap` for the region `virt`..`virt`+`size` in the virtual address space of
    /// the given activity.
    ///
    /// The given region in virtual memory must be physically contiguous and page aligned. Note that
    /// the preferred interface for this functionality is [`Activity::get_mem`].
    pub fn new_foreign(
        act: Selector,
        virt: VirtAddr,
        size: GlobOff,
        perm: Perm,
    ) -> Result<Self, Error> {
        let sel = SelSpace::get().alloc_sel();
        syscalls::create_mgate(sel, act, virt, size, perm)?;
        Ok(Self::new_owned_bind(sel))
    }

    /// Binds a new `MemCap` to the given selector.
    pub fn new_bind(sel: Selector) -> Self {
        Self {
            cap: Capability::new(sel, CapFlags::KEEP_CAP),
            resmng: false,
        }
    }

    /// Binds a new `MemCap` to the given selector and revokes the cap on drop.
    pub fn new_owned_bind(sel: Selector) -> Self {
        Self {
            cap: Capability::new(sel, CapFlags::empty()),
            resmng: false,
        }
    }

    /// Binds a new `MemCap` to the boot module with given name.
    pub fn new_bind_bootmod(name: &str) -> Result<Self, Error> {
        let sel = SelSpace::get().alloc_sel();
        Activity::own().resmng().unwrap().use_mod(sel, name)?;
        Ok(Self {
            cap: Capability::new(sel, CapFlags::empty()),
            resmng: false,
        })
    }

    /// Returns the selector of this `MemCap`
    pub fn sel(&self) -> Selector {
        self.cap.sel()
    }

    /// Returns the memory region (global address and size) this `MemCap` references.
    pub fn region(&self) -> Result<(GlobAddr, GlobOff), Error> {
        syscalls::mgate_region(self.sel())
    }

    /// Derives a new `MemCap` from `self` that has access to a subset of `self`'s the memory
    /// region and has a subset of `self`'s permissions. The subset of the memory region is defined
    /// by `offset` and `size` and the permissions by `perm`.
    ///
    /// Note that kernel makes sure that only owned permissions can be passed on to the derived
    /// `MemCap`.
    pub fn derive(&self, offset: GlobOff, size: GlobOff, perm: Perm) -> Result<Self, Error> {
        let sel = SelSpace::get().alloc_sel();
        self.derive_for(Activity::own().sel(), sel, offset, size, perm)
    }

    /// Like [`MemCap::derive`], but assigns the new `MemCap` to the given activity and uses given
    /// selector.
    pub fn derive_for(
        &self,
        act: Selector,
        sel: Selector,
        offset: GlobOff,
        size: GlobOff,
        perm: Perm,
    ) -> Result<Self, Error> {
        syscalls::derive_mem(act, sel, self.sel(), offset, size, perm)?;
        Ok(Self {
            cap: Capability::new(sel, CapFlags::empty()),
            resmng: false,
        })
    }

    /// Activates this capability on given endpoint and returns the resulting [`SendGate`]
    pub fn activate_on(self, ep: EP) -> Result<MemGate, Error> {
        self.do_activate_on(Some(ep))
    }

    fn do_activate_on(mut self, ep: Option<EP>) -> Result<MemGate, Error> {
        let gate = Gate::new(self.sel(), self.cap.flags(), ep)?;

        // prevent that we revoke the cap
        self.cap.set_flags(CapFlags::KEEP_CAP);

        Ok(MemGate {
            gate,
            resmng: self.resmng,
        })
    }
}

impl GateCap for MemCap {
    type Source = (Selector, bool);
    type Target = MemGate;

    fn new_from_cap(src: Self::Source) -> Self {
        Self {
            cap: Capability::new(src.0, CapFlags::KEEP_CAP),
            resmng: src.1,
        }
    }

    fn activate(self) -> Result<Self::Target, Error> {
        self.do_activate_on(None)
    }
}

impl Drop for MemCap {
    fn drop(&mut self) {
        if !self.cap.flags().contains(CapFlags::KEEP_CAP) && self.resmng {
            Activity::own().resmng().unwrap().free_mem(self.sel()).ok();
            self.cap.set_flags(CapFlags::KEEP_CAP);
        }
    }
}

/// Represents a contiguous region of memory, accessible via TCU
///
/// A memory gate provides access to a contiguous region of physical memory and allows RDMA-like
/// memory accesses via TCU. The physical memory can be located in a memory tile (e.g., DRAM), but
/// also in a compute tile. In the latter case it either refers to local memory (scratchpad) in the
/// destination tile or to physical memory located in another tile, but accessed through the cache
/// of the destination tile.
///
/// The following illustrates the difference with an example:
///
/// ```text
///    +-------------+        +--------------------------+
///    | Tile1       |        | Tile2                    |
///    | +---------+ |        | +---------+  +---------+ |
///    | |         | |        | |         |  |  Cache  | |
///    | |   TCU   | |    +---+->   TCU   +->+         | |
///    | |         | |    |   | |         |  |  BBCB   | |
///    | +----+----+ |    |   | +----+----+  |         | |
/// +--+-++ A | B ++-+----+   | |    |    |  |         | |
/// |  | +----+----+ |        | +----+----+  +----+----+ |
/// |  |             |        |                   |      |
/// |  +-------------+        +-------------------+------+
/// |                                             |
/// |  +------------------------------------------+------+
/// |  | Tile3                                    |      |
/// |  | +----------------------------------------+----+ |
/// |  | |                                        v    | |
/// +--+-+-->AAAA             DRAM              BBBB   | |
///    | |                                             | |
///    | +---------------------------------------------+ |
///    +-------------------------------------------------+
/// ```
///
/// The example above has two memory endpoints in Tile1's TCU (A and B). Endpoint A is directly
/// referring to the DRAM tile and thus sees the data `AAAA` in DRAM. In contrast, endpoint B refers
/// to the physical memory visible through the cache in Tile2. Therefore, endpoint B will see the
/// current state of the data in Tile2's cache (`BBCB`) instead of the potentially outdated data in
/// DRAM (`BBBB`).
///
/// Accessing physical memory through the cache of another tile therefore primarily exists because
/// tiles are not cache coherent. For example, it allows one application to get direct access to
/// data managed by another application.
///
/// The creation of `MemGate` therefore comes in two primary flavors: [`MemGate::new`] that
/// allocates new physical memory in DRAM and [`MemGate::new_foreign`] that provides access to a
/// physically contiguous physical memory region within another virtual address space.
///
/// Independent of the creation, every `MemGate` allows to issue DMA requests to the associated
/// memory region via [`MemGate::read`] and [`MemGate::write`].
pub struct MemGate {
    gate: Gate,
    resmng: bool,
}

/// The arguments for [`MemGate`] creations.
pub struct MGateArgs {
    size: GlobOff,
    perm: Perm,
    sel: Selector,
}

impl MGateArgs {
    /// Creates a new `MGateArgs` object with default settings
    pub fn new(size: GlobOff, perm: Perm) -> MGateArgs {
        MGateArgs {
            size,
            perm,
            sel: INVALID_SEL,
        }
    }

    /// Sets the capability selector that should be used for this [`MemGate`]. Otherwise and by
    /// default, [`SelSpace::get().alloc_sel`](crate::cap::SelSpace::alloc_sel) will be used to
    /// choose a free selector.
    pub fn sel(mut self, sel: Selector) -> Self {
        self.sel = sel;
        self
    }
}

impl MemGate {
    /// Creates a new `MemGate` that has access to a region of `size` bytes with permissions `perm`.
    ///
    /// This method will allocate `size` bytes with given permissions from the resource manager.
    pub fn new(size: GlobOff, perm: Perm) -> Result<Self, Error> {
        MemCap::new(size, perm)?.activate()
    }

    /// Creates a new `MemGate` with given arguments.
    ///
    /// This method will allocate `size` bytes with given permissions from the resource manager.
    pub fn new_with(args: MGateArgs) -> Result<Self, Error> {
        MemCap::new_with(args)?.activate()
    }

    /// Creates a new `MemGate` for the region `virt`..`virt`+`size` in the virtual address space of
    /// the given activity.
    ///
    /// The given region in virtual memory must be physically contiguous and page aligned. Note that
    /// the preferred interface for this functionality is [`Activity::get_mem`].
    pub fn new_foreign(
        act: Selector,
        virt: VirtAddr,
        size: GlobOff,
        perm: Perm,
    ) -> Result<Self, Error> {
        MemCap::new_foreign(act, virt, size, perm)?.activate()
    }

    /// Binds a new `MemGate` to the given selector.
    pub fn new_bind(sel: Selector) -> Result<Self, Error> {
        MemCap::new_bind(sel).activate()
    }

    /// Binds a new `MemGate` to the given selector and revokes the cap on drop.
    pub fn new_owned_bind(sel: Selector) -> Result<Self, Error> {
        MemCap::new_owned_bind(sel).activate()
    }

    /// Binds a new `MemGate` to the boot module with given name.
    pub fn new_bind_bootmod(name: &str) -> Result<Self, Error> {
        MemCap::new_bind_bootmod(name)?.activate()
    }

    /// Returns the selector of this gate
    pub fn sel(&self) -> Selector {
        self.gate.sel()
    }

    /// Returns the endpoint of the gate
    pub fn ep(&self) -> &EP {
        self.gate.ep()
    }

    /// Returns the memory region (global address and size) this `MemGate` references.
    pub fn region(&self) -> Result<(GlobAddr, GlobOff), Error> {
        syscalls::mgate_region(self.sel())
    }

    /// Like `MemCap::derive`, but creates a `MemGate`
    pub fn derive(&self, offset: GlobOff, size: GlobOff, perm: Perm) -> Result<Self, Error> {
        let sel = SelSpace::get().alloc_sel();
        self.derive_for(Activity::own().sel(), sel, offset, size, perm)
    }

    /// Derives a `MemCap` from this `MemGate`
    pub fn derive_cap(&self, offset: GlobOff, size: GlobOff, perm: Perm) -> Result<MemCap, Error> {
        MemCap::new_bind(self.sel()).derive(offset, size, perm)
    }

    /// Like `MemCap::derive_for`, but creates a `MemGate`
    pub fn derive_for(
        &self,
        act: Selector,
        sel: Selector,
        offset: GlobOff,
        size: GlobOff,
        perm: Perm,
    ) -> Result<Self, Error> {
        MemCap::new_bind(self.sel())
            .derive_for(act, sel, offset, size, perm)?
            .activate()
    }

    /// Uses the TCU read command to read from the memory region at offset `off` and stores the read
    /// data into a vector. The number of bytes to read is defined by the number of items and the
    /// size of `T`.
    #[allow(clippy::uninit_vec)]
    pub fn read_into_vec<T>(&self, items: usize, off: GlobOff) -> Result<Vec<T>, Error> {
        let mut vec = Vec::<T>::with_capacity(items);
        // we deliberately use uninitialize memory here, because it's performance critical
        // safety: this is okay, because the TCU does not read from `vec`
        unsafe { vec.set_len(items) };
        self.read(&mut vec, off)?;
        Ok(vec)
    }

    /// Uses the TCU read command to read from the memory region at offset `off` and stores the read
    /// data into the slice `data`. The number of bytes to read is defined by `data`.
    pub fn read<T>(&self, data: &mut [T], off: GlobOff) -> Result<(), Error> {
        tcu::TCU::read_slice(self.gate.ep().id(), data, off)
    }

    /// Reads `mem::size_of::<T>()` bytes via the TCU read command from the memory region at offset
    /// `off` and returns the data as an object of `T`.
    pub fn read_obj<T>(&self, off: GlobOff) -> Result<T, Error> {
        tcu::TCU::read_obj(self.gate.ep().id(), off)
    }

    /// Reads `size` bytes via the TCU read command from the memory region at offset `off` and
    /// stores the read data into `data`.
    pub fn read_bytes(&self, data: *mut u8, size: usize, off: GlobOff) -> Result<(), Error> {
        tcu::TCU::read(self.gate.ep().id(), data, size, off)
    }

    /// Writes `data` with the TCU write command to the memory region at offset `off`.
    pub fn write<T>(&self, data: &[T], off: GlobOff) -> Result<(), Error> {
        tcu::TCU::write_slice(self.gate.ep().id(), data, off)
    }

    /// Writes `obj` via the TCU write command to the memory region at offset `off`.
    pub fn write_obj<T>(&self, obj: &T, off: GlobOff) -> Result<(), Error> {
        tcu::TCU::write_obj(self.gate.ep().id(), obj, off)
    }

    /// Writes the `size` bytes at `data` via the TCU write command to the memory region at offset
    /// `off`.
    pub fn write_bytes(&self, data: *const u8, size: usize, off: GlobOff) -> Result<(), Error> {
        tcu::TCU::write(self.gate.ep().id(), data, size, off)
    }

    // /// Deactivates this `MemGate` and thereby turns it back into a `MemCap`
    pub fn deactivate(mut self) -> MemCap {
        let (resmng, flags) = (self.resmng, self.gate.flags());

        // invalidate and free the EP
        self.gate.release(true);

        // prevent that we revoke the cap or free the memory
        self.gate.set_flags(CapFlags::KEEP_CAP);
        self.resmng = false;

        MemCap {
            cap: Capability::new(self.sel(), flags),
            resmng,
        }
    }
}

impl Drop for MemGate {
    fn drop(&mut self) {
        if !self.gate.flags().contains(CapFlags::KEEP_CAP) && self.resmng {
            Activity::own().resmng().unwrap().free_mem(self.sel()).ok();
            self.gate.set_flags(CapFlags::KEEP_CAP);
        }
    }
}

impl fmt::Debug for MemGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "MemGate[sel: {}, ep: {:?}]",
            self.sel(),
            self.gate.ep().id()
        )
    }
}
