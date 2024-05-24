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
use base::kif::PageFlags;
use base::mem::{GlobAddr, GlobOff, PhysAddr, PhysAddrRaw, VirtAddr, VirtAddrRaw};
use base::tcu;
use base::util::math;

use paging::{AddrSpace, Allocator, ArchPaging, Paging};

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
        assert!(self.cur.as_raw() + cfg::PAGE_SIZE as PhysAddrRaw <= self.max.as_raw());
        self.cur += cfg::PAGE_SIZE as PhysAddrRaw;
        Ok(PhysAddr::new_raw(
            env::boot().tile_desc(),
            self.cur.as_raw() - cfg::PAGE_SIZE as PhysAddrRaw,
        ))
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
    let desc = env::boot().tile_desc();
    assert!(desc.has_virtmem());

    let (mem_tile, mem_base, mem_size, _) = tcu::TCU::unpack_mem_ep(0).unwrap();

    let base = GlobAddr::new_with(mem_tile, mem_base);
    let mut alloc = PTAllocator {
        pts_mapped: false,
        cur: PhysAddr::new(desc, 0, (mem_size / 2) as PhysAddrRaw),
        max: PhysAddr::new(desc, 0, mem_size as PhysAddrRaw),
    };
    let root = base + alloc.allocate_pt().unwrap().offset() as GlobOff;
    let aspace = AddrSpace::new(0, root, desc, alloc);
    aspace.init();
    ASPACE.set(aspace);

    // map TCU
    let rw = PageFlags::RW;
    for (mmio_addr, mmio_size, mmio_perm) in tcu::TCU::mmio_areas() {
        if mmio_size == 0 {
            continue;
        }

        // always read-write, because we need to write to our own EPs
        map_ident(mmio_addr, mmio_size, mmio_perm | rw);
    }

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
    let (env_start, env_size) = desc.env_space();
    map_ident(env_start, env_size, rw);

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
            base + (frame.offset() as GlobOff),
            1,
            perm,
        )?;
    }
    Ok(())
}

pub fn map_ident(virt: VirtAddr, size: usize, perm: PageFlags) {
    map_global(virt, GlobAddr::new(virt.as_goff()), size, perm);
}

pub fn map_global(virt: VirtAddr, glob: GlobAddr, size: usize, perm: PageFlags) {
    ASPACE
        .borrow_mut()
        .map_pages(virt, glob, size / cfg::PAGE_SIZE, perm)
        .unwrap();
}

#[allow(unused)]
pub fn unmap(virt: VirtAddr, size: usize) {
    ASPACE
        .borrow_mut()
        .map_pages(
            virt,
            GlobAddr::new(0),
            size / cfg::PAGE_SIZE,
            PageFlags::empty(),
        )
        .unwrap();
}

fn map_segment(start: *const u8, end: *const u8, perm: PageFlags) {
    let start_addr = math::round_dn(start as usize, cfg::PAGE_SIZE);
    let end_addr = math::round_up(end as usize, cfg::PAGE_SIZE);
    map_ident(VirtAddr::from(start_addr), end_addr - start_addr, perm);
}
