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

#![feature(ptr_internals)]
#![no_std]

#[macro_use]
mod log;

mod args;
mod cap;
mod com;
mod ktcu;
mod mem;
mod platform;
mod runtime;
mod slab;
mod syscalls;
mod tiles;

use base::cfg;
use base::env;
use base::goff;
use base::io;
use base::kif::TileDesc;
use base::machine;
use base::tcu;
use base::util::math;

use core::ptr;

use crate::tiles::{tilemng, ActivityMng};

extern "C" {
    fn __m3_init_libc(argc: i32, argv: *const *const u8, envp: *const *const u8);
    fn __m3_heap_get_end() -> usize;
    fn __m3_heap_append(pages: usize);
}

#[no_mangle]
pub extern "C" fn abort() -> ! {
    exit(1);
}

#[no_mangle]
pub extern "C" fn exit(_code: i32) -> ! {
    klog!(DEF, "Shutting down");
    machine::write_coverage(0);
    machine::shutdown();
}

fn create_rbufs() {
    let sysc_slot_size = 9;
    let sysc_rbuf_size = math::next_log2(cfg::MAX_ACTS) + sysc_slot_size;
    let serv_slot_size = 8;
    let serv_rbuf_size = math::next_log2(crate::com::MAX_PENDING_MSGS) + serv_slot_size;
    let tm_slot_size = 7;
    let tm_rbuf_size = math::next_log2(cfg::MAX_ACTS) + tm_slot_size;
    let total_size = (1 << sysc_rbuf_size) + (1 << serv_rbuf_size) + (1 << tm_rbuf_size);

    let tiledesc = TileDesc::new_from(env::data().tile_desc);
    let mut rbuf = if tiledesc.has_virtmem() {
        // we need to make sure that receive buffers are physically contiguous. thus, allocate a new
        // chunk of physical memory and map it somewhere.
        let total_size = math::round_up(total_size, cfg::PAGE_SIZE);
        let rbuf = cfg::RBUF_STD_ADDR;
        runtime::paging::map_new_mem(rbuf, total_size / cfg::PAGE_SIZE, cfg::PAGE_SIZE);
        rbuf
    }
    else {
        tiledesc.rbuf_space().0
    };

    // TODO add second syscall REP
    ktcu::recv_msgs(ktcu::KSYS_EP, rbuf as goff, sysc_rbuf_size, sysc_slot_size)
        .expect("Unable to config syscall REP");
    rbuf += 1 << sysc_rbuf_size as usize;

    ktcu::recv_msgs(ktcu::KSRV_EP, rbuf as goff, serv_rbuf_size, serv_slot_size)
        .expect("Unable to config service REP");
    rbuf += 1 << serv_rbuf_size as usize;

    ktcu::recv_msgs(ktcu::KPEX_EP, rbuf as goff, tm_rbuf_size, tm_slot_size)
        .expect("Unable to config tilemux REP");
}

fn extend_heap() {
    if platform::tile_desc(platform::kernel_tile()).has_virtmem() {
        let free_contiguous = mem::borrow_mut().largest_contiguous(mem::MemType::KERNEL);
        if let Some(bytes) = free_contiguous {
            let heap_end = unsafe { __m3_heap_get_end() };

            // determine page count and virtual start address
            let pages = (bytes as usize) >> cfg::PAGE_BITS;
            let virt = math::round_up(heap_end, cfg::PAGE_SIZE);

            // first map small pages until the next large page
            let virt_next_lpage = (virt + cfg::LPAGE_SIZE - 1) & !(cfg::LPAGE_SIZE - 1);
            let small_pages = (virt_next_lpage - virt) >> cfg::PAGE_BITS;

            runtime::paging::map_new_mem(virt, small_pages, cfg::PAGE_SIZE);
            unsafe { __m3_heap_append(small_pages) };

            // now map the rest with large pages
            let large_pages = ((pages - small_pages) * cfg::PAGE_SIZE) / cfg::LPAGE_SIZE;
            let pages_per_lpage = cfg::LPAGE_SIZE / cfg::PAGE_SIZE;
            runtime::paging::map_new_mem(
                virt_next_lpage,
                large_pages * pages_per_lpage,
                cfg::LPAGE_SIZE,
            );
            unsafe { __m3_heap_append(large_pages * pages_per_lpage) };
        }
    }
}

#[no_mangle]
pub extern "C" fn env_run() {
    unsafe { __m3_init_libc(0, ptr::null(), ptr::null()) };
    io::init(
        tcu::TileId::new_from_raw(env::data().tile_id as u16),
        "kernel",
    );
    crate::slab::init();

    runtime::paging::init();
    runtime::exceptions::init();
    crate::com::init_queues();

    klog!(DEF, "Entered raw mode; Quit via Ctrl+]");

    args::parse();

    platform::init();
    create_rbufs();
    extend_heap();
    thread::init();
    tiles::init();

    klog!(DEF, "Kernel is ready!");

    workloop();
}

pub fn thread_startup() {
    workloop();
}

fn workloop() -> ! {
    if thread::cur().is_main() {
        ActivityMng::start_root_async().expect("starting root failed");
    }

    while ActivityMng::count() > 0 {
        if env::data().platform != env::Platform::HW.val {
            tcu::TCU::sleep().unwrap();
        }

        if let Some(msg) = ktcu::fetch_msg(ktcu::KSYS_EP) {
            syscalls::handle_async(msg);
        }

        if let Some(msg) = ktcu::fetch_msg(ktcu::KSRV_EP) {
            unsafe {
                let squeue: *mut com::SendQueue = msg.header.label() as *mut _;
                (*squeue).received_reply(msg);
            }
        }

        if let Some(msg) = ktcu::fetch_msg(ktcu::KPEX_EP) {
            let tile = tcu::TileId::new_from_raw(msg.header.label() as u16);
            crate::tiles::TileMux::handle_call_async(crate::tiles::tilemng::tilemux(tile), msg);
        }

        thread::try_yield();
    }

    thread::stop();
    // if we get back here, there is no ready or sleeping thread anymore and we can shutdown

    if env::data().platform == env::Platform::GEM5.val {
        let mut sent = 0;
        for tile in platform::user_tiles() {
            if platform::tile_desc(tile).is_programmable() {
                tilemng::tilemux(tile).shutdown().unwrap();
                sent += 1;
            }
        }

        let mut replies = 0;
        while replies < sent {
            tcu::TCU::sleep().unwrap();
            if let Some(msg) = ktcu::fetch_msg(ktcu::KSRV_EP) {
                unsafe {
                    let squeue: *mut com::SendQueue = msg.header.label() as *mut _;
                    (*squeue).received_reply(msg);
                    replies += 1;
                }
            }
        }
    }

    tiles::deinit();
    exit(0);
}
