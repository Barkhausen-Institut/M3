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
use base::kif::PageFlags;
use base::mem::{GlobAddr, GlobOff, PhysAddr, PhysAddrRaw, VirtAddr, VirtAddrRaw};
use base::tcu;
use base::util::math;

use paging::{AddrSpace, Allocator, ArchPaging, Paging};

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
        assert!(self.cur.as_raw() + cfg::PAGE_SIZE as PhysAddrRaw <= self.max.as_raw());
        self.cur += cfg::PAGE_SIZE as PhysAddrRaw;
        Ok(PhysAddr::new_raw(
            env::boot().tile_desc(),
            self.cur.as_raw() - cfg::PAGE_SIZE as PhysAddrRaw,
        ))
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
    let desc = env::boot().tile_desc();
    if !desc.has_virtmem() {
        Paging::disable();
        return;
    }

    #[cfg(target_arch = "riscv32")]
    assert!(false, "Virtual memory is not yet supported on RV32");

    let (mem_tile, mem_base, mem_size, _) = tcu::TCU::unpack_mem_ep(0).unwrap();

    let base = GlobAddr::new_with(mem_tile, mem_base);
    let mut alloc = PTAllocator {
        cur: PhysAddr::new(desc, 0, (mem_size / 2) as PhysAddrRaw),
        max: PhysAddr::new(desc, 0, mem_size as PhysAddrRaw),
    };
    let root = base + alloc.allocate_pt().unwrap().offset() as GlobOff;
    let mut aspace = AddrSpace::new(tiles::KERNEL_ID as u64, root, desc, alloc);
    aspace.init();

    // map TCU
    let rw = PageFlags::RW;
    for (mmio_addr, mmio_size, mmio_perm) in tcu::TCU::mmio_areas() {
        if mmio_size == 0 {
            continue;
        }
        // all pages RW for the kernel
        map_ident(&mut aspace, mmio_addr, mmio_size, mmio_perm | rw);
    }

    // map text, data, and bss
    let rw = PageFlags::RW;
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
    let (env_start, env_size) = desc.env_space();
    map_to_phys(&mut aspace, base, env_start, env_size, rw);

    // map PTs
    let pages = mem_size as usize / cfg::PAGE_SIZE;
    aspace
        .map_pages(cfg::TILE_MEM_BASE, base, pages, rw)
        .unwrap();

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
            (pages * cfg::PAGE_SIZE) as GlobOff,
            align as GlobOff,
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
    let glob = base + (virt.as_goff() - env::boot().tile_desc().mem_offset() as GlobOff);
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
