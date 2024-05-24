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

use base::cfg;
use base::kif::{PageFlags, TileDesc};
use base::mem::{PhysAddr, PhysAddrRaw, VirtAddr};
use base::write_csr;

use bitflags::bitflags;

use core::arch::asm;

use crate::ArchMMUFlags;

pub type MMUPTE = u64;

pub const PTE_BITS: usize = 3;

pub const LEVEL_CNT: usize = 4;
pub const LEVEL_BITS: usize = cfg::PAGE_BITS - PTE_BITS;
pub const LEVEL_MASK: usize = (1 << LEVEL_BITS) - 1;

bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct X86MMUFlags : MMUPTE {
        const P     = 0b0000_0001;
        const W     = 0b0000_0010;
        const U     = 0b0000_0100;
        const L     = 0b1000_0000;
        const NX    = 0x8000_0000_0000_0000;

        const RW    = Self::P.bits() | Self::W.bits() | Self::NX.bits();
        const RWX   = Self::P.bits() | Self::W.bits();

        const FLAGS = cfg::PAGE_MASK as MMUPTE | Self::NX.bits();
    }
}

impl ArchMMUFlags for X86MMUFlags {
    fn has_empty_perm(&self) -> bool {
        !self.contains(Self::P)
    }

    fn is_leaf(&self, level: usize) -> bool {
        level == 0 || self.contains(Self::L)
    }

    fn access_allowed(&self, flags: Self) -> bool {
        self.contains(Self::P)
            && !(!self.contains(Self::W) && flags.contains(Self::W))
            && !(self.contains(Self::NX) && !flags.contains(Self::NX))
    }
}

pub struct X86Paging {}

impl crate::ArchPaging for X86Paging {
    type MMUFlags = X86MMUFlags;

    fn build_pte(phys: PhysAddr, perm: Self::MMUFlags, level: usize, leaf: bool) -> MMUPTE {
        let pte = phys.as_raw() as MMUPTE | perm.bits();
        if leaf {
            if level > 0 {
                pte | Self::MMUFlags::L.bits()
            }
            else {
                pte
            }
        }
        else {
            pte | (Self::MMUFlags::RWX | Self::MMUFlags::U).bits()
        }
    }

    fn pte_to_phys(tile_desc: TileDesc, pte: MMUPTE) -> PhysAddr {
        PhysAddr::new_raw(
            tile_desc,
            (pte & !Self::MMUFlags::FLAGS.bits()) as PhysAddrRaw,
        )
    }

    fn needs_invalidate(new_flags: Self::MMUFlags, old_flags: Self::MMUFlags) -> bool {
        old_flags.bits() != 0 && !new_flags.access_allowed(old_flags)
    }

    fn to_page_flags(_level: usize, pte: Self::MMUFlags) -> PageFlags {
        let mut res = PageFlags::empty();
        if pte.contains(Self::MMUFlags::P) {
            res |= PageFlags::R;
        }
        if pte.contains(Self::MMUFlags::W) {
            res |= PageFlags::W;
        }
        if pte.contains(Self::MMUFlags::U) {
            res |= PageFlags::U;
        }
        if !pte.contains(Self::MMUFlags::NX) {
            res |= PageFlags::X;
        }
        if pte.contains(Self::MMUFlags::L) {
            res |= PageFlags::L;
        }
        res
    }

    fn to_mmu_perms(flags: PageFlags) -> Self::MMUFlags {
        let mut res = Self::MMUFlags::empty();
        if flags.intersects(PageFlags::RWX) {
            res |= Self::MMUFlags::P;
        }
        if flags.contains(PageFlags::W) {
            res |= Self::MMUFlags::W;
        }
        if flags.contains(PageFlags::U) {
            res |= Self::MMUFlags::U;
        }
        if !flags.contains(PageFlags::X) {
            res |= Self::MMUFlags::NX;
        }
        res
    }

    fn enable() {
        // already enabled by gem5
    }

    fn disable() {
        // not possible/necessary
    }

    fn invalidate_page(_id: crate::ActId, virt: VirtAddr) {
        unsafe {
            asm!(
                "invlpg [{0}]",
                in(reg) virt.as_local(),
                options(nostack),
            );
        }
    }

    fn invalidate_tlb() {
        // nothing to do
    }

    fn set_root_pt(_id: crate::ActId, root: PhysAddr) {
        write_csr!("cr3", root.as_raw() as usize);
    }
}
