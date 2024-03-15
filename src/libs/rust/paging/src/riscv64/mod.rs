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

use base::cell::LazyStaticCell;
use base::cfg;
use base::kif::PageFlags;
use base::mem::{PhysAddr, PhysAddrRaw, VirtAddr};
use base::{read_csr, set_csr_bits, write_csr};

use bitflags::bitflags;

use core::arch::asm;

use crate::ArchMMUFlags;

pub type MMUPTE = u64;

pub const PTE_BITS: usize = 3;

pub const LEVEL_CNT: usize = 3;
pub const LEVEL_BITS: usize = cfg::PAGE_BITS - PTE_BITS;
pub const LEVEL_MASK: usize = (1 << LEVEL_BITS) - 1;

pub const MODE_BARE: u64 = 0;
pub const MODE_SV39: u64 = 8;

bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct RISCV64MMUFlags : MMUPTE {
        const V     = 0b0000_0001;          // valid
        const R     = 0b0100_0010;          // readable
                                            // note: the accessed bit is set here, because the
                                            // RocketCore raises a PF if unset instead of setting
                                            // the bit itself.
        const W     = 0b1000_0100;          // writable (same here with the dirty bit)
        const X     = 0b0100_1000;          // executable (same here with the accessed bit)
        const U     = 0b0001_0000;          // user accessible
        const G     = 0b0010_0000;          // global
        const A     = 0b0100_0000;          // accessed
        const D     = 0b1000_0000;          // dirty

        const RW    = Self::V.bits() | Self::R.bits() | Self::W.bits();
        const RWX   = Self::RW.bits() | Self::X.bits();

        const FLAGS = 0xFFu64;
    }
}

impl ArchMMUFlags for RISCV64MMUFlags {
    fn has_empty_perm(&self) -> bool {
        !self.contains(Self::V)
    }

    fn is_leaf(&self, _level: usize) -> bool {
        (*self & (Self::R | Self::W | Self::X)) != Self::empty()
    }

    fn access_allowed(&self, flags: Self) -> bool {
        if !self.contains(Self::V) {
            return false;
        }
        !self.is_leaf(0) || (*self & flags) == flags
    }
}

pub struct RISCV64Paging {}

impl crate::ArchPaging for RISCV64Paging {
    type MMUFlags = RISCV64MMUFlags;

    fn build_pte(phys: PhysAddr, perm: Self::MMUFlags, _level: usize, leaf: bool) -> MMUPTE {
        if leaf {
            if perm.has_empty_perm() {
                0
            }
            else {
                (phys.as_raw() >> 2) as MMUPTE | (Self::MMUFlags::V | perm).bits()
            }
        }
        else {
            (phys.as_raw() >> 2) as MMUPTE | Self::MMUFlags::V.bits()
        }
    }

    fn pte_to_phys(pte: MMUPTE) -> PhysAddr {
        PhysAddr::new_raw(((pte & !Self::MMUFlags::FLAGS.bits()) << 2) as PhysAddrRaw)
    }

    fn needs_invalidate(_new_flags: Self::MMUFlags, _old_flags: Self::MMUFlags) -> bool {
        // according to 4.2.1, we need an invalidate whenever a leaf PTE is updated
        true
    }

    fn to_page_flags(level: usize, pte: Self::MMUFlags) -> PageFlags {
        let mut res = PageFlags::empty();
        if pte.contains(Self::MMUFlags::V) {
            res |= PageFlags::R;
        }
        else {
            return res;
        }

        if pte.contains(Self::MMUFlags::W) {
            res |= PageFlags::W;
        }
        if pte.contains(Self::MMUFlags::X) {
            res |= PageFlags::X;
        }
        if pte.contains(Self::MMUFlags::U) {
            res |= PageFlags::U;
        }
        if level > 0 {
            res |= PageFlags::L;
        }
        res
    }

    fn to_mmu_perms(flags: PageFlags) -> Self::MMUFlags {
        let mut res = Self::MMUFlags::empty();
        if flags.intersects(PageFlags::RWX) {
            res |= Self::MMUFlags::V;
        }
        if flags.contains(PageFlags::R) {
            res |= Self::MMUFlags::R;
        }
        if flags.contains(PageFlags::W) {
            res |= Self::MMUFlags::W;
        }
        if flags.contains(PageFlags::X) {
            res |= Self::MMUFlags::X;
        }
        if flags.contains(PageFlags::U) {
            res |= Self::MMUFlags::U;
        }
        res
    }

    fn enable() {
        // set sstatus.SUM = 1 to allow accesses to user memory (required for TCU)
        set_csr_bits!("sstatus", 1 << 18);
    }

    fn disable() {
        set_csr_bits!("sstatus", 0);
        write_csr!("satp", MODE_BARE);
    }

    fn invalidate_page(id: crate::ActId, virt: VirtAddr) {
        unsafe {
            asm!(
                "sfence.vma {0}, {1}",
                in(reg) virt.as_local(),
                in(reg) id,
                options(nomem, nostack),
            );
        }
    }

    fn invalidate_tlb() {
        unsafe {
            asm!("sfence.vma", options(nomem, nostack));
        }
    }

    fn set_root_pt(id: crate::ActId, root: PhysAddr) {
        static MAX_ASID: LazyStaticCell<crate::ActId> = LazyStaticCell::default();
        if !MAX_ASID.is_some() {
            // determine how many ASID bits are supported (see 4.1.12)
            let satp = MODE_SV39 << 60 | 0xFFFF << 44;
            write_csr!("satp", satp);
            let actual_satp = read_csr!("satp");
            MAX_ASID.set(((actual_satp >> 44) & 0xFFFF) as crate::ActId);
        }

        let satp: u64 = MODE_SV39 << 60 | id << 44 | (root.as_raw() as u64 >> cfg::PAGE_BITS);
        write_csr!("satp", satp);

        // if there are not enough ASIDs, always flush the TLB
        // TODO we could do better here by assigning each activity to an ASID within 0..MAX_ASID and flush
        // whenever we don't change the ASID. however, the Rocket Core has MAX_ASID=0, so that it's not
        // worth it right now.
        if MAX_ASID.get() != 0xFFFF {
            Self::invalidate_tlb();
        }
    }
}