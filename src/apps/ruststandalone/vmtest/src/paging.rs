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

use base::cell::LazyStaticRefCell;
use base::cfg;
use base::env;
use base::errors::Error;
use base::goff;
use base::kif::{PageFlags, TileDesc};
use base::mem::{GlobAddr, PhysAddr, PhysAddrRaw, VirtAddr, VirtAddrRaw};
use base::tcu;
use base::util::math;

use paging::{self, AddrSpace, Allocator, ArchPaging, Paging};

extern "C" {
    static _text_start: u8;
    static _text_end: u8;
    static _data_start: u8;
    static _data_end: u8;
    static _bss_start: u8;
    static _bss_end: u8;
}

struct PTAllocator {
    pts_mapped: bool,
    cur: PhysAddr,
    max: PhysAddr,
}

impl Allocator for PTAllocator {
    fn allocate_pt(&mut self) -> Result<PhysAddr, Error> {
        assert!(self.cur + cfg::PAGE_SIZE as PhysAddrRaw <= self.max);
        self.cur += cfg::PAGE_SIZE as PhysAddrRaw;
        Ok(self.cur - PhysAddr::new_raw(cfg::PAGE_SIZE as PhysAddrRaw))
    }

    fn translate_pt(&self, phys: PhysAddr) -> VirtAddr {
        if !self.pts_mapped {
            VirtAddr::new(phys.as_raw() as VirtAddrRaw)
        }
        else {
            cfg::TILE_MEM_BASE + phys.offset() as VirtAddrRaw
        }
    }

    fn free_pt(&mut self, _phys: PhysAddr) {
        unimplemented!();
    }
}

static ASPACE: LazyStaticRefCell<AddrSpace<PTAllocator>> = LazyStaticRefCell::default();

pub fn init() {
    assert!(TileDesc::new_from(env::boot().tile_desc).has_virtmem());

    let (mem_tile, mem_base, mem_size, _) = tcu::TCU::unpack_mem_ep(0).unwrap();

    let base = GlobAddr::new_with(mem_tile, mem_base);
    let mut alloc = PTAllocator {
        pts_mapped: false,
        cur: PhysAddr::new(0, (mem_size / 2) as PhysAddrRaw),
        max: PhysAddr::new(0, mem_size as PhysAddrRaw),
    };
    let root = base + alloc.allocate_pt().unwrap().offset() as goff;
    let aspace = AddrSpace::new(0, root, alloc);
    aspace.init();
    ASPACE.set(aspace);

    // map TCU
    let rw = PageFlags::RW;
    map_ident(tcu::MMIO_ADDR, tcu::MMIO_SIZE, rw);
    map_ident(tcu::MMIO_PRIV_ADDR, tcu::MMIO_PRIV_SIZE, rw);
    map_ident(tcu::MMIO_PRIV_ADDR + cfg::PAGE_SIZE, cfg::PAGE_SIZE, rw);

    // map text, data, and bss
    unsafe {
        map_segment(&_text_start, &_text_end, PageFlags::RX);
        map_segment(&_data_start, &_data_end, PageFlags::RW);
        map_segment(&_bss_start, &_bss_end, PageFlags::RW);

        // map initial heap
        let heap_start = math::round_up(&_bss_end as *const _ as usize, cfg::PAGE_SIZE);
        map_ident(VirtAddr::from(heap_start), 4 * cfg::PAGE_SIZE, rw);
    }

    // map env
    map_ident(cfg::ENV_START, cfg::ENV_SIZE, rw);

    // map PTs
    let pages = mem_size as usize / cfg::PAGE_SIZE;
    ASPACE
        .borrow_mut()
        .map_pages(cfg::TILE_MEM_BASE, base, pages, rw)
        .unwrap();

    // map PLIC
    #[cfg(target_arch = "riscv64")]
    {
        map_ident(VirtAddr::from(0x0C00_0000), cfg::PAGE_SIZE, PageFlags::RW);
        map_ident(VirtAddr::from(0x0C00_2000), cfg::PAGE_SIZE, PageFlags::RW);
        map_ident(VirtAddr::from(0x0C20_1000), cfg::PAGE_SIZE, PageFlags::RW);
    }

    // switch to that address space
    ASPACE.borrow_mut().switch_to();
    Paging::enable();

    // now we can use the mapped-pts area
    ASPACE.borrow_mut().allocator_mut().pts_mapped = true;
}

#[allow(unused)]
pub fn translate(virt: VirtAddr, perm: PageFlags) -> (PhysAddr, PageFlags) {
    ASPACE.borrow().translate(virt, perm.bits())
}

#[allow(unused)]
pub fn map_anon(virt: VirtAddr, size: usize, perm: PageFlags) -> Result<(), Error> {
    let (mem_tile, mem_base, _, _) = tcu::TCU::unpack_mem_ep(0).unwrap();
    let base = GlobAddr::new_with(mem_tile, mem_base);

    for i in 0..(size / cfg::PAGE_SIZE) {
        let frame = ASPACE.borrow_mut().allocator_mut().allocate_pt()?;
        ASPACE.borrow_mut().map_pages(
            virt + i * cfg::PAGE_SIZE,
            base + (frame.offset() as goff),
            1,
            perm,
        )?;
    }
    Ok(())
}

pub fn map_ident(virt: VirtAddr, size: usize, perm: PageFlags) {
    let glob = GlobAddr::new(virt.as_goff());
    ASPACE
        .borrow_mut()
        .map_pages(virt, glob, size / cfg::PAGE_SIZE, perm)
        .unwrap();
}

fn map_segment(start: *const u8, end: *const u8, perm: PageFlags) {
    let start_addr = math::round_dn(start as usize, cfg::PAGE_SIZE);
    let end_addr = math::round_up(end as usize, cfg::PAGE_SIZE);
    map_ident(VirtAddr::from(start_addr), end_addr - start_addr, perm);
}
