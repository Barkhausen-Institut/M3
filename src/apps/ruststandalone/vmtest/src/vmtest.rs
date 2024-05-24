/*
 * Copyright (C) 2021-2022 Nils Asmussen, Barkhausen Institut
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

#[allow(unused_extern_crates)]
extern crate heap;

mod helper;
mod paging;

use base::cell::StaticCell;
use base::cfg;
use base::env;
use base::errors::{Code, Error};
use base::io::LogFlags;
use base::kif::{PageFlags, Perm};
use base::libc;
use base::log;
use base::machine;
use base::mem::{size_of, GlobAddr, MsgBuf, PhysAddr, PhysAddrRaw, VirtAddr};
use base::tcu::{self, EpId, TileId, TCU};
use base::util;

use core::intrinsics::transmute;
use core::ptr;
use core::sync::atomic;

use isr::{ISRArch, StateArch, ISR};

static OWN_TILE: TileId = TileId::new(0, 0);
static MEM_TILE: TileId = TileId::new(0, 8);

static OWN_ACT: u16 = 0xFFFF;
static CU_REQS: StaticCell<u64> = StaticCell::new(0);

static MEP: EpId = tcu::FIRST_USER_EP;
static SEP: EpId = tcu::FIRST_USER_EP + 1;
static REP1: EpId = tcu::FIRST_USER_EP + 2;
static RPLEP: EpId = tcu::FIRST_USER_EP + 3;
static REP2: EpId = tcu::FIRST_USER_EP + 4;

pub extern "C" fn mmu_pf(state: &mut isr::State) -> *mut libc::c_void {
    let (virt, perm) = ISR::get_pf_info(state);

    panic!(
        "Pagefault for address={}, perm={:?} with {:?}",
        virt, perm, state
    );
}

fn read_write(wr_addr: VirtAddr, rd_addr: VirtAddr, size: usize) {
    log!(
        LogFlags::Info,
        "WRITE to {} and READ back into {} with {} bytes",
        wr_addr,
        rd_addr,
        size
    );

    TCU::invalidate_tlb();

    let wr_slice = unsafe { util::slice_for_mut(wr_addr.as_mut_ptr(), size) };
    let rd_slice = unsafe { util::slice_for_mut(rd_addr.as_mut_ptr(), size) };

    // prepare test data
    for i in 0..size {
        wr_slice[i] = i as u8;
        rd_slice[i] = 0;
    }

    // configure mem EP
    helper::config_local_ep(MEP, |regs| {
        TCU::config_mem(regs, OWN_ACT, MEM_TILE, 0x4000_0000, size, Perm::RW);
    });

    // test write + read
    TCU::write(MEP, wr_slice.as_ptr(), size, 0).unwrap();
    TCU::read(MEP, rd_slice.as_mut_ptr(), size, 0).unwrap();

    assert_eq!(rd_slice, wr_slice);
}

fn test_mem(area_begin: VirtAddr, area_size: usize) {
    helper::XLATES.set(0);
    let mut count = 0;

    let rd_area = area_begin;
    let wr_area = area_begin + area_size / 2;

    // same page
    {
        read_write(wr_area, wr_area + 16usize, 16);
        count += 1;
        assert_eq!(helper::XLATES.get(), count);
    }

    // different pages, one page each
    {
        read_write(wr_area, rd_area, 16);
        count += 2;
        assert_eq!(helper::XLATES.get(), count);
    }

    // unaligned
    {
        read_write(wr_area + 1usize, rd_area, 3);
        count += 2;
        assert_eq!(helper::XLATES.get(), count);
    }

    // unaligned write with page boundary
    {
        read_write(wr_area + 1usize, rd_area, cfg::PAGE_SIZE);
        count += 3;
        assert_eq!(helper::XLATES.get(), count);
    }

    // unaligned read with page boundary
    {
        read_write(wr_area, rd_area + 1usize, cfg::PAGE_SIZE);
        count += 3;
        assert_eq!(helper::XLATES.get(), count);
    }
}

static RBUF1: [u64; 32] = [0; 32];
static RBUF2: [u64; 32] = [0; 32];

fn send_recv(send_addr: VirtAddr, size: usize) {
    log!(
        LogFlags::Info,
        "SEND+REPLY from {} with {} bytes",
        send_addr,
        size * 8
    );

    TCU::invalidate_tlb();

    // create receive buffers
    let (rbuf1_virt, rbuf1_phys) = helper::virt_to_phys(VirtAddr::from(RBUF1.as_ptr()));
    let (rbuf2_virt, rbuf2_phys) = helper::virt_to_phys(VirtAddr::from(RBUF2.as_ptr()));

    // create EPs
    let max_msg_ord = util::math::next_log2(size_of::<tcu::Header>() + size * 8);
    assert!(RBUF1.len() * size_of::<u64>() >= 1 << max_msg_ord);
    helper::config_local_ep(REP1, |regs| {
        TCU::config_recv(
            regs,
            OWN_ACT,
            rbuf1_phys,
            max_msg_ord,
            max_msg_ord,
            Some(RPLEP),
        );
    });
    helper::config_local_ep(REP2, |regs| {
        TCU::config_recv(regs, OWN_ACT, rbuf2_phys, max_msg_ord, max_msg_ord, None);
    });
    helper::config_local_ep(SEP, |regs| {
        TCU::config_send(regs, OWN_ACT, 0x1234, OWN_TILE, REP1, max_msg_ord, 1);
    });

    let msg_buf: &mut MsgBuf = unsafe { transmute(send_addr.as_local()) };

    // prepare test data
    unsafe {
        for i in 0..size {
            msg_buf.words_mut()[i] = i as u64;
        }
        msg_buf.set_size(size * 8)
    };

    // send message
    TCU::send(SEP, msg_buf, 0x1111, REP2).unwrap();

    {
        // fetch message
        let rmsg = loop {
            if let Some(m) = helper::fetch_msg(REP1, rbuf1_virt) {
                break m;
            }
        };
        assert_eq!(rmsg.header.label(), 0x1234);
        let recv_slice = unsafe { util::slice_for(rmsg.data.as_ptr(), rmsg.header.length()) };
        assert_eq!(msg_buf.bytes(), recv_slice);

        // send reply
        TCU::reply(REP1, msg_buf, tcu::TCU::msg_to_offset(rbuf1_virt, rmsg)).unwrap();
    }

    {
        // fetch reply
        let rmsg = loop {
            if let Some(m) = helper::fetch_msg(REP2, rbuf2_virt) {
                break m;
            }
        };
        assert_eq!(rmsg.header.label(), 0x1111);
        let recv_slice = unsafe { util::slice_for(rmsg.data.as_ptr(), rmsg.header.length()) };
        assert_eq!(msg_buf.bytes(), recv_slice);

        // ack reply
        tcu::TCU::ack_msg(REP2, tcu::TCU::msg_to_offset(rbuf2_virt, rmsg)).unwrap();
    }
}

#[repr(C, align(4096))]
struct LargeAlignedBuf {
    bytes: [u8; cfg::PAGE_SIZE + 16],
}

fn test_msgs(area_begin: VirtAddr, _area_size: usize) {
    helper::XLATES.set(0);
    let mut count = 0;

    let (_rbuf1_virt, rbuf1_phys) = helper::virt_to_phys(VirtAddr::from(RBUF1.as_ptr()));

    {
        log!(LogFlags::Info, "SEND with page boundary");

        let buf = LargeAlignedBuf {
            bytes: [0u8; cfg::PAGE_SIZE + 16],
        };

        helper::config_local_ep(REP1, |regs| {
            TCU::config_recv(regs, OWN_ACT, rbuf1_phys, 6, 6, None);
        });
        helper::config_local_ep(SEP, |regs| {
            TCU::config_send(regs, OWN_ACT, 0x5678, OWN_TILE, REP1, 6, 1);
        });
        let buf_addr = unsafe { buf.bytes.as_ptr().add(cfg::PAGE_SIZE - 16) };
        assert_eq!(
            TCU::send_aligned(SEP, buf_addr, 32, 0x1111, tcu::NO_REPLIES),
            Err(Error::new(Code::PageBoundary))
        );
    }

    {
        log!(LogFlags::Info, "REPLY with page boundary");

        let buf = LargeAlignedBuf {
            bytes: [0u8; cfg::PAGE_SIZE + 16],
        };

        helper::config_local_ep(REP1, |regs| {
            TCU::config_recv(regs, OWN_ACT, rbuf1_phys, 6, 6, Some(RPLEP));
            // make the message occupied
            regs[2] = 1;
        });
        helper::config_local_ep(RPLEP, |regs| {
            TCU::config_send(regs, OWN_ACT, 0x5678, OWN_TILE, REP1, 6, 1);
            // make it a reply EP
            #[cfg(any(feature = "hw22", feature = "hw23"))]
            {
                regs[0] |= 1 << 53;
            }
            #[cfg(not(any(feature = "hw22", feature = "hw23")))]
            {
                regs[0] |= 1 << 55;
            }
        });
        let buf_addr = unsafe { buf.bytes.as_ptr().add(cfg::PAGE_SIZE - 16) };
        assert_eq!(
            TCU::reply_aligned(REP1, buf_addr, 32, 0),
            Err(Error::new(Code::PageBoundary))
        );
    }

    // small
    {
        send_recv(area_begin, 1);
        count += 1;
        assert_eq!(helper::XLATES.get(), count);
    }

    // large
    {
        send_recv(area_begin, 16);
        count += 1;
        assert_eq!(helper::XLATES.get(), count);
    }
}

static EXPECTED_CU_REQ: StaticCell<Option<tcu::CUReq>> = StaticCell::new(None);

pub extern "C" fn tcu_irq(state: &mut isr::State) -> *mut libc::c_void {
    log!(LogFlags::Info, "Got TCU IRQ @ {}", state.instr_pointer());

    ISR::fetch_irq();

    // CU request from TCU?
    let req = tcu::TCU::get_cu_req();
    log!(LogFlags::Info, "Got {:x?}", req);
    assert_eq!(req, EXPECTED_CU_REQ.get());

    if req.is_some() {
        CU_REQS.set(CU_REQS.get() + 1);
    }

    tcu::TCU::set_cu_resp();

    state as *mut _ as *mut libc::c_void
}

fn test_foreign_msg() {
    CU_REQS.set(0);

    let (rbuf1_virt, rbuf1_phys) = helper::virt_to_phys(VirtAddr::from(RBUF1.as_ptr()));

    log!(LogFlags::Info, "SEND to REP of foreign Activity");

    // create EPs
    helper::config_local_ep(REP1, |regs| {
        TCU::config_recv(regs, 0xDEAD, rbuf1_phys, 6, 6, None);
    });
    helper::config_local_ep(SEP, |regs| {
        TCU::config_send(regs, OWN_ACT, 0x5678, OWN_TILE, REP1, 6, 1);
    });

    EXPECTED_CU_REQ.set(Some(tcu::CUReq::ForeignReceive {
        act: 0xDEAD,
        ep: REP1,
    }));
    // ensure that EXPECTED_CU_REQ is set first
    atomic::fence(atomic::Ordering::SeqCst);

    // send message
    let buf = MsgBuf::new();
    assert_eq!(TCU::send(SEP, &buf, 0x1111, tcu::NO_REPLIES), Ok(()));

    // wait for CU request
    while unsafe { ptr::read_volatile(CU_REQS.as_ptr()) } == 0 {}
    assert_eq!(CU_REQS.get(), 1);
    EXPECTED_CU_REQ.set(None);

    // switch to foreign activity (we have received a message)
    let old = TCU::xchg_activity((1 << 16) | 0xDEAD).unwrap();
    // we had no unread messages
    assert_eq!(old, OWN_ACT as u64);
    // but now we have one
    assert_eq!(TCU::get_cur_activity(), (1 << 16) | 0xDEAD);

    // fetch message with foreign activity
    let msg = helper::fetch_msg(REP1, rbuf1_virt).unwrap();
    assert_eq!(msg.header.label(), 0x5678);
    // message is fetched
    assert_eq!(TCU::get_cur_activity(), 0xDEAD);
    tcu::TCU::ack_msg(REP1, tcu::TCU::msg_to_offset(rbuf1_virt, msg)).unwrap();

    // no unread messages anymore
    let foreign = TCU::xchg_activity(old).unwrap();
    assert_eq!(foreign, 0xDEAD);
}

fn test_own_msg() {
    CU_REQS.set(0);

    let (rbuf1_virt, rbuf1_phys) = helper::virt_to_phys(VirtAddr::from(RBUF1.as_ptr()));

    log!(LogFlags::Info, "SEND to REP of own Activity");

    // create EPs
    helper::config_local_ep(REP1, |regs| {
        TCU::config_recv(regs, OWN_ACT, rbuf1_phys, 6, 6, None);
    });
    helper::config_local_ep(SEP, |regs| {
        TCU::config_send(regs, OWN_ACT, 0x5678, OWN_TILE, REP1, 6, 1);
    });

    // no message yet
    assert_eq!(TCU::get_cur_activity(), OWN_ACT as u64);

    // send message
    let buf = MsgBuf::new();
    assert_eq!(TCU::send(SEP, &buf, 0x1111, tcu::NO_REPLIES), Ok(()));

    // wait until it arrived
    while !TCU::has_msgs(REP1) {}
    // now we have a message
    assert_eq!(TCU::get_cur_activity(), (1 << 16) | OWN_ACT as u64);

    // fetch message
    let msg = helper::fetch_msg(REP1, rbuf1_virt).unwrap();
    assert_eq!(msg.header.label(), 0x5678);
    // message is fetched
    assert_eq!(TCU::get_cur_activity(), OWN_ACT as u64);
    tcu::TCU::ack_msg(REP1, tcu::TCU::msg_to_offset(rbuf1_virt, msg)).unwrap();

    // no foreign message CU requests here
    assert_eq!(CU_REQS.get(), 0);
}

fn test_pmp_failures() {
    CU_REQS.set(0);

    // flush the cache to be sure that the reads cause cache misses
    unsafe { machine::flush_cache() };

    // the physical address is only invalid on RISC-V (where we have a base offset of 0x1000_0000)
    #[cfg(target_arch = "riscv64")]
    {
        // invalid physical address
        let virt = VirtAddr::from(0x3000_0000);
        paging::map_global(virt, GlobAddr::new(0), cfg::PAGE_SIZE, PageFlags::RW);

        EXPECTED_CU_REQ.set(Some(tcu::CUReq::PMPFailure {
            phys: 0,
            write: false,
            error: Code::NoPMPEP,
        }));
        // ensure that EXPECTED_CU_REQ is set first
        atomic::fence(atomic::Ordering::SeqCst);

        let addr = virt.as_mut_ptr::<u8>();
        let _val = unsafe { ptr::read_volatile(addr) };

        // use read_volatile to ensure that we actually perform memory accesses (not register loads)
        while unsafe { ptr::read_volatile(CU_REQS.as_ptr()) } != 1 {}
        assert_eq!(CU_REQS.get(), 1);

        EXPECTED_CU_REQ.set(None);
        paging::unmap(virt, cfg::PAGE_SIZE);
    }

    let pmpep0 = tcu::TCU::unpack_mem_ep(0).unwrap();
    let base_off = pmpep0.1 + pmpep0.2;

    assert_eq!(tcu::TCU::unpack_mem_ep(1), None);
    helper::config_local_ep(1, |regs| {
        TCU::config_mem(regs, OWN_ACT, MEM_TILE, base_off, cfg::PAGE_SIZE, Perm::RW);
    });

    CU_REQS.set(0);

    {
        // beyond bounds
        let virt = VirtAddr::from(0x4000_0000);
        let global = GlobAddr::new_with(MEM_TILE, base_off);
        let size = cfg::PAGE_SIZE;
        paging::map_global(virt, global, size * 2, PageFlags::RW);
        atomic::fence(atomic::Ordering::SeqCst);

        let addr = virt.as_mut_ptr::<u8>();

        // that's okay
        let _val = unsafe { ptr::read_volatile(addr) };

        // change EP to read-only (cannot do that before, because otherwise map_global fails)
        helper::config_local_ep(1, |regs| {
            TCU::config_mem(regs, OWN_ACT, MEM_TILE, base_off, cfg::PAGE_SIZE, Perm::R);
        });

        EXPECTED_CU_REQ.set(Some(tcu::CUReq::PMPFailure {
            phys: global
                .to_phys(env::boot().tile_desc(), PageFlags::R)
                .unwrap()
                .as_raw()
                + cfg::PAGE_SIZE as u32,
            write: false,
            error: Code::OutOfBounds,
        }));
        atomic::fence(atomic::Ordering::SeqCst);
        let _val = unsafe { ptr::read_volatile(addr.add(cfg::PAGE_SIZE)) };

        while unsafe { ptr::read_volatile(CU_REQS.as_ptr()) } != 1 {}
        assert_eq!(CU_REQS.get(), 1);

        EXPECTED_CU_REQ.set(Some(tcu::CUReq::PMPFailure {
            phys: global
                .to_phys(env::boot().tile_desc(), PageFlags::R)
                .unwrap()
                .as_raw(),
            write: true,
            error: Code::NoPerm,
        }));
        atomic::fence(atomic::Ordering::SeqCst);
        unsafe { ptr::write_volatile(addr, 0x77) };
        // flush the cache to trigger a LLC miss
        unsafe { machine::flush_cache() };

        while unsafe { ptr::read_volatile(CU_REQS.as_ptr()) } != 2 {}
        assert_eq!(CU_REQS.get(), 2);
        EXPECTED_CU_REQ.set(None);

        paging::unmap(virt, size * 2);
    }
}

fn test_tlb() {
    const TLB_SIZE: usize = 32;
    const ASID: u16 = 1;

    {
        log!(LogFlags::Info, "Testing non-fixed TLB entries");

        TCU::invalidate_tlb();

        // fill with lots of entries (beyond capacity)
        let mut virt = VirtAddr::from(0x2000_0000);
        let mut phys = PhysAddr::new(env::boot().tile_desc(), 0, 0);
        for _ in 0..TLB_SIZE * 2 {
            TCU::insert_tlb(ASID, virt, phys, PageFlags::RW).unwrap();
            virt += cfg::PAGE_SIZE;
            phys += cfg::PAGE_SIZE as PhysAddrRaw;
        }

        // this entry should be found (no error)
        TCU::invalidate_page(ASID, virt - cfg::PAGE_SIZE).unwrap();
        // this should not be found
        assert_eq!(
            TCU::invalidate_page(ASID, virt - cfg::PAGE_SIZE),
            Err(Error::new(Code::TLBMiss)),
        );
    }

    {
        log!(LogFlags::Info, "Testing fixed TLB entries");

        TCU::invalidate_tlb();

        // fill with lots of fixed entries
        let mut virt = VirtAddr::from(0x2000_0000);
        let mut phys = PhysAddr::new(env::boot().tile_desc(), 0, 0);
        for _ in 0..TLB_SIZE {
            TCU::insert_tlb(ASID, virt, phys, PageFlags::RW | PageFlags::FIXED).unwrap();
            virt += cfg::PAGE_SIZE;
            phys += cfg::PAGE_SIZE as PhysAddrRaw;
        }

        // now the TLB is full and we should get an error
        assert_eq!(
            TCU::insert_tlb(ASID, virt, phys, PageFlags::RW | PageFlags::FIXED),
            Err(Error::new(Code::TLBFull)),
        );
        assert_eq!(
            TCU::insert_tlb(ASID, virt, phys, PageFlags::RW),
            Err(Error::new(Code::TLBFull))
        );
        // but the same address can still be inserted
        TCU::insert_tlb(
            ASID,
            VirtAddr::from(0x2000_0000),
            phys,
            PageFlags::R | PageFlags::FIXED,
        )
        .unwrap();

        // remove all fixed entries
        let virt = VirtAddr::from(0x2000_0000);
        for i in 0..TLB_SIZE {
            TCU::invalidate_page(ASID, virt + cfg::PAGE_SIZE * i).unwrap();
        }
    }

    {
        log!(LogFlags::Info, "Testing removal of TLB entries");

        TCU::invalidate_tlb();

        // insert entries with different flags
        let virt = VirtAddr::from(0x2000_0000);
        let phys = PhysAddr::new(env::boot().tile_desc(), 0, 0);
        let pgsz = cfg::PAGE_SIZE;
        TCU::insert_tlb(ASID, virt, phys, PageFlags::R).unwrap();
        TCU::insert_tlb(ASID, virt + pgsz * 1, phys, PageFlags::W).unwrap();
        TCU::insert_tlb(ASID, virt + pgsz * 2, phys, PageFlags::RW).unwrap();
        TCU::insert_tlb(ASID, virt + pgsz * 3, phys, PageFlags::R | PageFlags::FIXED).unwrap();
        TCU::insert_tlb(ASID, virt + pgsz * 4, phys, PageFlags::W | PageFlags::FIXED).unwrap();
        TCU::insert_tlb(
            ASID,
            virt + pgsz * 5,
            phys,
            PageFlags::RW | PageFlags::FIXED,
        )
        .unwrap();

        // remove all these entries explicitly
        for i in 0..=5 {
            TCU::invalidate_page(ASID, virt + pgsz * i).unwrap();
        }

        // now the TLB should be empty again, so that we can fill it with fixed entries
        for i in 0..TLB_SIZE {
            TCU::insert_tlb(ASID, virt + pgsz * i, phys, PageFlags::R | PageFlags::FIXED).unwrap();
            // overwrite existing entry
            TCU::insert_tlb(ASID, virt + pgsz * i, phys, PageFlags::R | PageFlags::FIXED).unwrap();
        }

        // remove all fixed entries
        for i in 0..TLB_SIZE {
            TCU::invalidate_page(ASID, virt + pgsz * i).unwrap();
        }
    }

    TCU::invalidate_tlb();
}

macro_rules! run_test {
    ($name:ident($( $arg:expr ),*)) => {{
        log!(LogFlags::Info, "-- Running {} --", stringify!($name));
        $name($( $arg ),*);
    }};
}

#[no_mangle]
pub extern "C" fn env_run() {
    ISR::reg_page_faults(mmu_pf);
    ISR::reg_cu_reqs(tcu_irq);

    helper::init("vmtest");

    let virt = env::boot().tile_desc().env_space().0;
    let (phys, flags) = paging::translate(virt, PageFlags::R);
    log!(
        LogFlags::Info,
        "Translated virt={} to ({}, {:?})",
        virt,
        phys,
        flags
    );

    log!(LogFlags::Info, "Mapping memory area...");
    let area_begin = VirtAddr::from(0xC100_0000);
    let area_size = cfg::PAGE_SIZE * 8;
    paging::map_anon(area_begin, area_size, PageFlags::RW).expect("Unable to map memory");

    run_test!(test_mem(area_begin, area_size));
    run_test!(test_msgs(area_begin, area_size));
    run_test!(test_foreign_msg());
    run_test!(test_own_msg());
    run_test!(test_pmp_failures());
    run_test!(test_tlb());

    log!(LogFlags::Info, "Shutting down");
    helper::exit(0);
}
