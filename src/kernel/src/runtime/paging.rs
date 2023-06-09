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

use base::cell::{LazyStaticRefCell, StaticCell};
use base::cfg;
use base::env;
use base::errors::Error;
use base::goff;
use base::kif::{PageFlags, TileDesc};
use base::mem::{GlobAddr, PhysAddr, PhysAddrRaw, VirtAddr, VirtAddrRaw};
use base::tcu;
use base::util::math;

use paging::{self, AddrSpace, Allocator, ArchPaging, Paging};

use crate::mem;
use crate::tiles;

extern "C" {
    static _text_start: u8;
    static _text_end: u8;
    static _data_start: u8;
    static _data_end: u8;
    static _bss_start: u8;
    static _bss_end: u8;

    fn __m3_heap_get_area(begin: *mut usize, end: *mut usize);
}

struct PTAllocator {
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
        if BOOTSTRAP.get() {
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

static BOOTSTRAP: StaticCell<bool> = StaticCell::new(true);
static ASPACE: LazyStaticRefCell<AddrSpace<PTAllocator>> = LazyStaticRefCell::default();

pub fn init() {
    if !TileDesc::new_from(env::boot().tile_desc).has_virtmem() {
        Paging::disable();
        return;
    }

    let (mem_tile, mem_base, mem_size, _) = tcu::TCU::unpack_mem_ep(0).unwrap();

    let base = GlobAddr::new_with(mem_tile, mem_base);
    let mut alloc = PTAllocator {
        cur: PhysAddr::new(0, (mem_size / 2) as PhysAddrRaw),
        max: PhysAddr::new(0, mem_size as PhysAddrRaw),
    };
    let root = base + alloc.allocate_pt().unwrap().offset() as goff;
    let mut aspace = AddrSpace::new(tiles::KERNEL_ID as u64, root, alloc);
    aspace.init();

    // map TCU
    let rw = PageFlags::RW;
    map_ident(&mut aspace, tcu::MMIO_ADDR, tcu::MMIO_SIZE, rw);
    map_ident(&mut aspace, tcu::MMIO_PRIV_ADDR, tcu::MMIO_PRIV_SIZE, rw);

    // map text, data, and bss
    unsafe {
        map_segment(&mut aspace, base, &_text_start, &_text_end, PageFlags::RX);
        map_segment(&mut aspace, base, &_data_start, &_data_end, PageFlags::RW);
        map_segment(&mut aspace, base, &_bss_start, &_bss_end, PageFlags::RW);

        // map initial heap
        let mut heap_start = 0;
        let mut heap_end = 0;
        __m3_heap_get_area(&mut heap_start, &mut heap_end);
        map_to_phys(
            &mut aspace,
            base,
            VirtAddr::from(heap_start),
            heap_end - heap_start,
            rw,
        );
    }

    // map env
    map_to_phys(&mut aspace, base, cfg::ENV_START, cfg::ENV_SIZE, rw);

    // map PTs
    let pages = mem_size as usize / cfg::PAGE_SIZE;
    aspace
        .map_pages(cfg::TILE_MEM_BASE, base, pages, rw)
        .unwrap();

    // map vectors
    #[cfg(target_arch = "arm")]
    map_to_phys(
        &mut aspace,
        base,
        VirtAddr::null(),
        cfg::PAGE_SIZE,
        PageFlags::RX,
    );

    // switch to that address space
    aspace.switch_to();
    Paging::enable();

    ASPACE.set(aspace);
    BOOTSTRAP.set(false);
}

pub fn translate(virt: VirtAddr, perm: PageFlags) -> (PhysAddr, PageFlags) {
    ASPACE.borrow().translate(virt, perm.bits())
}

pub fn map_new_mem(virt: VirtAddr, pages: usize, align: usize) -> GlobAddr {
    let alloc = mem::borrow_mut()
        .allocate(
            mem::MemType::KERNEL,
            (pages * cfg::PAGE_SIZE) as goff,
            align as goff,
        )
        .unwrap();

    ASPACE
        .borrow_mut()
        .map_pages(virt, alloc.global(), pages, PageFlags::RW)
        .unwrap();
    alloc.global()
}

fn map_ident(aspace: &mut AddrSpace<PTAllocator>, virt: VirtAddr, size: usize, perm: PageFlags) {
    let glob = GlobAddr::new(virt.as_goff());
    aspace
        .map_pages(virt, glob, size / cfg::PAGE_SIZE, perm)
        .unwrap();
}

fn map_to_phys(
    aspace: &mut AddrSpace<PTAllocator>,
    base: GlobAddr,
    virt: VirtAddr,
    size: usize,
    perm: PageFlags,
) {
    let glob = base + (virt.as_goff() - cfg::MEM_OFFSET as goff);
    aspace
        .map_pages(virt, glob, size / cfg::PAGE_SIZE, perm)
        .unwrap();
}

fn map_segment(
    aspace: &mut AddrSpace<PTAllocator>,
    base: GlobAddr,
    start: *const u8,
    end: *const u8,
    perm: PageFlags,
) {
    let start_addr = math::round_dn(VirtAddr::from(start), VirtAddr::from(cfg::PAGE_SIZE));
    let end_addr = math::round_up(VirtAddr::from(end), VirtAddr::from(cfg::PAGE_SIZE));
    map_to_phys(
        aspace,
        base,
        start_addr,
        (end_addr - start_addr).as_local(),
        perm,
    );
}
