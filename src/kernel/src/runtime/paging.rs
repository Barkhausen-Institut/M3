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

use base::cell::{LazyStaticCell, LazyStaticRefCell, StaticCell};
use base::cfg;
use base::env;
use base::errors::Error;
use base::goff;
use base::kif::{PageFlags, TileDesc, PTE};
use base::mem::GlobAddr;
use base::tcu;
use base::util::math;

use paging::{self, AddrSpace, Allocator, Phys};

use crate::mem;
use crate::tiles;

extern "C" {
    static _text_start: u8;
    static _text_end: u8;
    static _data_start: u8;
    static _data_end: u8;
    static _bss_start: u8;
    static _bss_end: u8;

    fn __m3_heap_set_area(begin: usize, end: usize);
    fn __m3_heap_get_end() -> usize;
}

struct PTAllocator {}

impl Allocator for PTAllocator {
    fn allocate_pt(&mut self) -> Result<Phys, Error> {
        PT_POS.set(PT_POS.get() + cfg::PAGE_SIZE as goff);
        Ok(PT_POS.get() - cfg::PAGE_SIZE as goff)
    }

    fn translate_pt(&self, phys: Phys) -> usize {
        if BOOTSTRAP.get() {
            phys as usize
        }
        else {
            cfg::TILE_MEM_BASE + (phys as usize - cfg::MEM_OFFSET)
        }
    }

    fn free_pt(&mut self, _phys: Phys) {
        unimplemented!();
    }
}

static BOOTSTRAP: StaticCell<bool> = StaticCell::new(true);
static PT_POS: LazyStaticCell<goff> = LazyStaticCell::default();
static ASPACE: LazyStaticRefCell<AddrSpace<PTAllocator>> = LazyStaticRefCell::default();

pub fn init() {
    if !TileDesc::new_from(env::data().tile_desc).has_virtmem() {
        paging::disable_paging();
        return;
    }

    let (mem_tile, mem_base, mem_size, _) = tcu::TCU::unpack_mem_ep(0).unwrap();

    let base = GlobAddr::new_with(mem_tile, mem_base);
    let root = base + mem_size / 2;
    let pts_phys = cfg::MEM_OFFSET as goff + mem_size / 2;
    PT_POS.set(pts_phys + cfg::PAGE_SIZE as goff);
    let mut aspace = AddrSpace::new(tiles::KERNEL_ID as u64, root, PTAllocator {});
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
        let heap_start = math::round_up(&_bss_end as *const _ as usize, cfg::PAGE_SIZE);
        let mut heap_end = __m3_heap_get_end();
        if heap_end == 0 {
            // if the heap has not been used yet, set the heap area
            heap_end = heap_start + 64 * cfg::PAGE_SIZE;
            __m3_heap_set_area(heap_start, heap_end);
        }
        map_to_phys(&mut aspace, base, heap_start, heap_end - heap_start, rw);
    }

    // map env
    map_to_phys(
        &mut aspace,
        base,
        cfg::ENV_START & !cfg::PAGE_MASK,
        cfg::ENV_SIZE,
        rw,
    );

    // map PTs
    let pages = mem_size as usize / cfg::PAGE_SIZE;
    aspace
        .map_pages(cfg::TILE_MEM_BASE, base, pages, rw)
        .unwrap();

    // map vectors
    #[cfg(target_arch = "arm")]
    map_to_phys(&mut aspace, base, 0, cfg::PAGE_SIZE, PageFlags::RX);

    // switch to that address space
    aspace.switch_to();
    paging::enable_paging();

    ASPACE.set(aspace);
    BOOTSTRAP.set(false);
}

pub fn translate(virt: usize, perm: PageFlags) -> PTE {
    ASPACE.borrow().translate(virt, perm.bits())
}

pub fn map_new_mem(virt: usize, pages: usize, align: usize) -> GlobAddr {
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

fn map_ident(aspace: &mut AddrSpace<PTAllocator>, virt: usize, size: usize, perm: PageFlags) {
    let glob = GlobAddr::new(virt as goff);
    aspace
        .map_pages(virt, glob, size / cfg::PAGE_SIZE, perm)
        .unwrap();
}

fn map_to_phys(
    aspace: &mut AddrSpace<PTAllocator>,
    base: GlobAddr,
    virt: usize,
    size: usize,
    perm: PageFlags,
) {
    let glob = base + (virt - cfg::MEM_OFFSET) as Phys;
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
    let start_addr = math::round_dn(start as usize, cfg::PAGE_SIZE);
    let end_addr = math::round_up(end as usize, cfg::PAGE_SIZE);
    map_to_phys(aspace, base, start_addr, end_addr - start_addr, perm);
}
