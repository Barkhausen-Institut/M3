/*
 * Copyright (C) 2024 Nils Asmussen, Barkhausen Institut
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
use base::mem::{PhysAddr, VirtAddr};
use base::{set_csr_bits, write_csr};

use bitflags::bitflags;

use crate::ArchMMUFlags;

// TODO the spec indicates that RV32 only supports Sv32 paging, which is not supported by gem5 and
// the cores on the hardware platform don't support it either. We thus have this empty dummy
// implementation for now.

pub type MMUPTE = u32;

pub const PTE_BITS: usize = 2;

pub const LEVEL_CNT: usize = 2;
pub const LEVEL_BITS: usize = cfg::PAGE_BITS - PTE_BITS;
pub const LEVEL_MASK: usize = (1 << LEVEL_BITS) - 1;

pub const MODE_BARE: usize = 0;

bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct RISCV32MMUFlags : MMUPTE {
    }
}

impl ArchMMUFlags for RISCV32MMUFlags {
    fn has_empty_perm(&self) -> bool {
        false
    }

    fn is_leaf(&self, _level: usize) -> bool {
        false
    }

    fn access_allowed(&self, _flags: Self) -> bool {
        false
    }
}

pub struct RISCV32Paging {}

impl crate::ArchPaging for RISCV32Paging {
    type MMUFlags = RISCV32MMUFlags;

    fn build_pte(_phys: PhysAddr, _perm: Self::MMUFlags, _level: usize, _leaf: bool) -> MMUPTE {
        0
    }

    fn pte_to_phys(_tile_desc: TileDesc, _pte: MMUPTE) -> PhysAddr {
        PhysAddr::default()
    }

    fn needs_invalidate(_new_flags: Self::MMUFlags, _old_flags: Self::MMUFlags) -> bool {
        true
    }

    fn to_page_flags(_level: usize, _pte: Self::MMUFlags) -> PageFlags {
        PageFlags::empty()
    }

    fn to_mmu_perms(_flags: PageFlags) -> Self::MMUFlags {
        Self::MMUFlags::empty()
    }

    fn enable() {
    }

    fn disable() {
        set_csr_bits!("sstatus", 0);
        write_csr!("satp", MODE_BARE);
    }

    fn invalidate_page(_id: crate::ActId, _virt: VirtAddr) {
    }

    fn invalidate_tlb() {
    }

    fn set_root_pt(_id: crate::ActId, _root: PhysAddr) {
    }
}
