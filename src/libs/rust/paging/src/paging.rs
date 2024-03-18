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

#![no_std]

use base::cfg;
use base::errors::Error;
use base::io::LogFlags;
use base::kif::{PageFlags, PTE};
use base::libc;
use base::log;
use base::mem::{size_of, GlobAddr, GlobOff, PhysAddr, PhysAddrRaw, VirtAddr};
use base::tcu::TCU;
use base::util::math;
use core::fmt;

use arch::{LEVEL_BITS, LEVEL_CNT, LEVEL_MASK};

pub type ActId = u64;

pub trait ArchMMUFlags {
    /// Returns true if the flags are empty
    fn has_empty_perm(&self) -> bool;

    /// Returns true if this flags define a leaf-PTE at given level
    fn is_leaf(&self, level: usize) -> bool;

    /// Returns true if the access with given flags is allowed
    fn access_allowed(&self, flags: Self) -> bool;
}

/// Captures all architecture-dependent parts and is therefore implemented for each support ISA
pub trait ArchPaging {
    type MMUFlags: ArchMMUFlags;

    /// Builds a page table entry with given configuration
    fn build_pte(phys: PhysAddr, perm: Self::MMUFlags, level: usize, leaf: bool) -> MMUPTE;

    // Retrieves the physical address from given page table entry
    fn pte_to_phys(pte: MMUPTE) -> PhysAddr;

    /// Checks whether the given flag change requires a TLB invalidation
    fn needs_invalidate(new_flags: Self::MMUFlags, old_flags: Self::MMUFlags) -> bool;

    /// Converts the given architecture-specific `MMUFlags` to the generic `PageFlags`
    fn to_page_flags(level: usize, pte: Self::MMUFlags) -> PageFlags;
    /// Converts the given generic `PageFlags` to the architecture-specific `MMUFlags`
    fn to_mmu_perms(flags: PageFlags) -> Self::MMUFlags;

    /// Enables paging, i.e., manipulates the control registers so that virtual address are
    /// afterwards translated to physical addresses.
    fn enable();
    fn disable();

    /// Invalidates the entry in the TLB for given activity and virtual address
    fn invalidate_page(id: ActId, virt: VirtAddr);

    /// Invalidates all entries in the TLB
    fn invalidate_tlb();

    /// Sets the root page table to given physical address and activity
    fn set_root_pt(id: ActId, root: PhysAddr);
}

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        #[path = "x86_64/mod.rs"]
        mod arch;
        pub type Paging = arch::X86Paging;
        pub type MMUFlags = <arch::X86Paging as ArchPaging>::MMUFlags;
    }
    else if #[cfg(target_arch = "arm")] {
        #[path = "arm/mod.rs"]
        mod arch;
        pub type Paging = arch::ARMPaging;
        pub type MMUFlags = <arch::ARMPaging as ArchPaging>::MMUFlags;
    }
    else if #[cfg(target_arch = "riscv64")] {
        #[path = "riscv64/mod.rs"]
        mod arch;
        pub type Paging = arch::RISCV64Paging;
        pub type MMUFlags = <arch::RISCV64Paging as ArchPaging>::MMUFlags;
    }
    else if #[cfg(target_arch = "riscv32")] {
        #[path = "riscv32/mod.rs"]
        mod arch;
        pub type Paging = arch::RISCV32Paging;
        pub type MMUFlags = <arch::RISCV32Paging as ArchPaging>::MMUFlags;
    }
}

pub use arch::MMUPTE;

pub trait Allocator {
    /// Allocates a new page table and returns its physical address
    fn allocate_pt(&mut self) -> Result<PhysAddr, Error>;

    /// Translates the given physical address of a page table to a virtual address
    fn translate_pt(&self, phys: PhysAddr) -> VirtAddr;

    /// Frees the given page table
    fn free_pt(&mut self, phys: PhysAddr);
}

pub struct AddrSpace<A: Allocator> {
    id: ActId,
    root: MMUPTE,
    alloc: A,
}

impl<A: Allocator> AddrSpace<A> {
    pub fn new(id: ActId, root: GlobAddr, alloc: A) -> Self {
        let phys = root.to_phys(PageFlags::RW).unwrap();
        AddrSpace {
            id,
            root: Paging::build_pte(phys, MMUFlags::empty(), LEVEL_CNT, false),
            alloc,
        }
    }

    pub fn id(&self) -> ActId {
        self.id
    }

    pub fn allocator(&self) -> &A {
        &self.alloc
    }

    pub fn allocator_mut(&mut self) -> &mut A {
        &mut self.alloc
    }

    pub fn switch_to(&self) {
        Paging::set_root_pt(self.id, Paging::pte_to_phys(self.root));
    }

    pub fn flush_tlb(&self) {
        Paging::invalidate_tlb();
    }

    pub fn init(&self) {
        let root_phys = Paging::pte_to_phys(self.root);
        let pt_virt = self.alloc.translate_pt(root_phys);
        Self::clear_pt(pt_virt);
    }

    pub fn translate(&self, virt: VirtAddr, perm: PTE) -> (PhysAddr, PageFlags) {
        // otherwise, walk through all levels
        let perm = Paging::to_mmu_perms(PageFlags::from_bits_truncate(perm));
        let mut pte = self.root;
        for lvl in (0..LEVEL_CNT).rev() {
            let pt_virt = self.alloc.translate_pt(Paging::pte_to_phys(pte));
            let idx = (virt.as_local() >> (cfg::PAGE_BITS + lvl * LEVEL_BITS)) & LEVEL_MASK;
            let pte_addr = pt_virt + idx * size_of::<MMUPTE>();

            // safety: as above
            pte = unsafe { *pte_addr.as_ptr::<MMUPTE>() };

            let pte_flags = MMUFlags::from_bits_truncate(pte);
            if pte_flags.is_leaf(lvl) || !pte_flags.access_allowed(perm) {
                let res = Paging::pte_to_phys(pte);
                let flags = MMUFlags::from_bits_truncate(pte);
                return (res, Paging::to_page_flags(lvl, flags));
            }
        }
        unreachable!();
    }

    pub fn map_pages(
        &mut self,
        mut virt: VirtAddr,
        global: GlobAddr,
        mut pages: usize,
        perm: PageFlags,
    ) -> Result<(), Error> {
        let mut phys = global.to_phys(perm)?;

        log!(
            LogFlags::PgMap,
            "Activity{}: mapping {}..{} to {}..{} ({}) with {:?}",
            self.id,
            virt,
            virt + pages * cfg::PAGE_SIZE - 1,
            global,
            global + (pages * cfg::PAGE_SIZE - 1) as GlobOff,
            phys,
            perm
        );

        let lvl = LEVEL_CNT - 1;
        let perm = Paging::to_mmu_perms(perm);
        self.map_pages_rec(&mut virt, &mut phys, &mut pages, perm, self.root, lvl)
    }

    fn map_pages_rec(
        &mut self,
        virt: &mut VirtAddr,
        phys: &mut PhysAddr,
        pages: &mut usize,
        perm: MMUFlags,
        pte: MMUPTE,
        level: usize,
    ) -> Result<(), Error> {
        // determine virtual address for page table
        let pt_virt = self.alloc.translate_pt(Paging::pte_to_phys(pte));

        // start at the corresponding index
        let idx = ((*virt).as_local() >> (cfg::PAGE_BITS + level * LEVEL_BITS)) & LEVEL_MASK;
        let mut pte_addr = pt_virt + idx * size_of::<MMUPTE>();

        while *pages > 0 {
            // reached end of page table?
            if pte_addr >= pt_virt + cfg::PAGE_SIZE {
                break;
            }

            // safety: as above
            let mut pte = unsafe { *pte_addr.as_ptr::<MMUPTE>() };

            let is_leaf = if perm.has_empty_perm() {
                MMUFlags::from_bits_truncate(pte).is_leaf(level)
            }
            else {
                level == 0
                // can we use a large page?
                || (level == 1
                    && math::is_aligned((*virt).as_local(), cfg::LPAGE_SIZE)
                    && math::is_aligned((*phys).as_raw(), cfg::LPAGE_SIZE as PhysAddrRaw)
                    && *pages * cfg::PAGE_SIZE >= cfg::LPAGE_SIZE)
            };

            if is_leaf {
                let psize = if level == 1 {
                    cfg::LPAGE_SIZE
                }
                else {
                    cfg::PAGE_SIZE
                };

                let new_pte = Paging::build_pte(*phys, perm, level, true);

                // determine if we need to perform an TLB invalidate
                let old_flags = MMUFlags::from_bits_truncate(pte);
                let new_flags = MMUFlags::from_bits_truncate(new_pte);

                // safety: as above
                unsafe { *pte_addr.as_mut_ptr::<MMUPTE>() = new_pte };

                let invalidate = Paging::needs_invalidate(new_flags, old_flags);
                if invalidate {
                    TCU::invalidate_page_unchecked(self.id as u16, *virt);
                    // flush single page for leaf PTEs and complete TLB for higher-level PTEs
                    if level == 0 {
                        Paging::invalidate_page(self.id, *virt);
                    }
                    else {
                        Paging::invalidate_tlb();
                    }
                }

                log!(
                    LogFlags::PgMapPages,
                    "Activity{}: lvl {} PTE for {}: 0x{:0>16x} (inv={}) @ {}",
                    self.id,
                    level,
                    virt,
                    new_pte,
                    invalidate,
                    pte_addr,
                );

                *pages -= psize / cfg::PAGE_SIZE;
                *virt += psize;
                *phys += psize as PhysAddrRaw;
            }
            else {
                // unmapping non-existing PTs is a noop
                if !(pte == 0 && perm.has_empty_perm()) {
                    if pte == 0 {
                        pte = self.create_pt(*virt, pte_addr, level)?;
                    }

                    self.map_pages_rec(virt, phys, pages, perm, pte, level - 1)?;
                }
            }

            pte_addr += size_of::<MMUPTE>();
        }

        Ok(())
    }

    fn create_pt(
        &mut self,
        virt: VirtAddr,
        pte_addr: VirtAddr,
        level: usize,
    ) -> Result<MMUPTE, Error> {
        let frame = self.alloc.allocate_pt()?;
        Self::clear_pt(self.alloc.translate_pt(frame));

        // insert PTE
        let pte = Paging::build_pte(frame, MMUFlags::empty(), level, false);
        // safety: as above
        unsafe { *pte_addr.as_mut_ptr::<MMUPTE>() = pte };

        let pt_size = (1 << (LEVEL_BITS * level)) * cfg::PAGE_SIZE;
        let virt_base = virt & VirtAddr::from(!(pt_size - 1));
        log!(
            LogFlags::PgMapPages,
            "Activity{}: lvl {} PTE for {}: 0x{:0>16x} @ {}",
            self.id,
            level,
            virt_base,
            pte,
            pte_addr,
        );

        Ok(pte)
    }

    fn clear_pt(pt_virt: VirtAddr) {
        unsafe { libc::memset(pt_virt.as_mut_ptr(), 0, cfg::PAGE_SIZE) };
    }

    fn free_pts_rec(&mut self, pt: MMUPTE, level: usize) {
        let mut ptes = self.alloc.translate_pt(Paging::pte_to_phys(pt));
        for _ in 0..1 << LEVEL_BITS {
            // safety: as above
            let pte = unsafe { *ptes.as_ptr::<MMUPTE>() };
            if pte != 0 {
                let pte_phys = Paging::pte_to_phys(pte);
                // does the PTE refer to a PT?
                if pte_phys.as_raw() != 0 && !MMUFlags::from_bits_truncate(pte).is_leaf(level) {
                    // there are no PTEs refering to PTs at level 0
                    if level > 1 {
                        self.free_pts_rec(pte, level - 1);
                    }
                    self.alloc.free_pt(pte_phys);
                }
            }

            ptes += size_of::<MMUPTE>();
        }
    }

    fn print_as_rec(
        &self,
        f: &mut fmt::Formatter<'_>,
        pt: MMUPTE,
        mut virt: VirtAddr,
        level: usize,
    ) -> Result<(), fmt::Error> {
        let mut ptes = self.alloc.translate_pt(Paging::pte_to_phys(pt));
        for _ in 0..1 << LEVEL_BITS {
            // safety: as above
            let pte = unsafe { *ptes.as_ptr::<MMUPTE>() };
            if pte != 0 {
                let w = (LEVEL_CNT - level - 1) * 2;
                writeln!(f, "{:w$}{}: 0x{:0>16x}", "", virt, pte, w = w)?;
                if !MMUFlags::from_bits_truncate(pte).is_leaf(level) {
                    self.print_as_rec(f, pte, virt, level - 1)?;
                }
            }

            virt += 1 << (level * LEVEL_BITS + cfg::PAGE_BITS);
            ptes += size_of::<MMUPTE>();
        }
        Ok(())
    }
}

impl<A: Allocator> Drop for AddrSpace<A> {
    fn drop(&mut self) {
        if Paging::pte_to_phys(self.root).as_raw() != 0 {
            self.free_pts_rec(self.root, LEVEL_CNT - 1);

            // invalidate entire TLB to allow us to reuse the activity id
            Paging::invalidate_tlb();
            TCU::invalidate_tlb();
        }
    }
}

impl<A: Allocator> fmt::Debug for AddrSpace<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "Address space @ {}:", Paging::pte_to_phys(self.root))?;
        self.print_as_rec(f, self.root, VirtAddr::null(), LEVEL_CNT - 1)
    }
}
