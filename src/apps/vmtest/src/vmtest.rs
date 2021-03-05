/*
 * Copyright (C) 2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
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

#![feature(llvm_asm)]
#![no_std]

extern crate heap;

mod paging;
mod pes;

use base::cell::{LazyStaticCell, StaticCell};
use base::cfg;
use base::io;
use base::kif::{PageFlags, Perm};
use base::libc;
use base::log;
use base::machine;
use base::math::next_log2;
use base::mem::{size_of, MsgBuf};
use base::tcu::{self, EpId, Message, Reg, EP_REGS, TCU};
use base::util;
use base::{read_csr, write_csr};

use core::intrinsics::transmute;

use pes::PE;

static LOG_DEF: bool = true;
static LOG_PEXCALLS: bool = false;

static OWN_VPE: u16 = 0xFFFF;
static STATE: LazyStaticCell<isr::State> = LazyStaticCell::default();
static XLATES: StaticCell<u64> = StaticCell::new(0);

#[no_mangle]
pub extern "C" fn abort() {
    exit(1);
}

#[no_mangle]
pub extern "C" fn exit(_code: i32) {
    machine::shutdown();
}

pub extern "C" fn mmu_pf(state: &mut isr::State) -> *mut libc::c_void {
    let virt = read_csr!("stval");

    let perm = match isr::Vector::from(state.cause & 0x1F) {
        isr::Vector::INSTR_PAGEFAULT => PageFlags::R | PageFlags::X,
        isr::Vector::LOAD_PAGEFAULT => PageFlags::R,
        isr::Vector::STORE_PAGEFAULT => PageFlags::R | PageFlags::W,
        _ => unreachable!(),
    };

    panic!(
        "Pagefault for address={:#x}, perm={:?} with {:?}",
        virt, perm, state
    );
}

pub extern "C" fn pexcall(state: &mut isr::State) -> *mut libc::c_void {
    let virt = state.r[isr::PEXC_ARG1] as usize;
    let access = Perm::from_bits_truncate(state.r[isr::PEXC_ARG2] as u32);
    let flags = PageFlags::from(access) & PageFlags::RW;

    log!(
        crate::LOG_PEXCALLS,
        "pexcall::tlb_miss(virt={:#x}, access={:?})",
        virt,
        access
    );

    XLATES.set(*XLATES + 1);

    let pte = paging::translate(virt, flags);
    // no page faults supported
    assert!(!(pte & PageFlags::RW.bits()) & flags.bits() == 0);
    log!(crate::LOG_PEXCALLS, "TCU can continue with PTE={:#x}", pte);

    // insert TLB entry
    let phys = pte & !(cfg::PAGE_MASK as u64);
    let flags = PageFlags::from_bits_truncate(pte & cfg::PAGE_MASK as u64);
    tcu::TCU::insert_tlb(OWN_VPE, virt, phys, flags);

    state as *mut _ as *mut libc::c_void
}

pub extern "C" fn sw_irq(state: &mut isr::State) -> *mut libc::c_void {
    log!(crate::LOG_DEF, "Got software IRQ @ {:#x}", state.epc);

    // disable software IRQ
    write_csr!("sip", read_csr!("sip") & !0x2);

    state as *mut _ as *mut libc::c_void
}

pub extern "C" fn timer_irq(state: &mut isr::State) -> *mut libc::c_void {
    log!(crate::LOG_DEF, "Got timer IRQ @ {:#x}", state.epc);

    let mtimecmp = 0x0200_4000 as *mut u64;
    let mtime = 0x0200_bff8 as *const u64;
    unsafe {
        // The frequency given by QEMU is 10_000_000 Hz, so this sets
        // the next interrupt to fire one second from now.
        mtimecmp.write_volatile(mtime.read_volatile() + 10_000_000);
    }

    state as *mut _ as *mut libc::c_void
}

fn config_local_ep<CFG>(ep: EpId, cfg: CFG)
where
    CFG: FnOnce(&mut [Reg]),
{
    let mut regs = [0 as Reg; EP_REGS];
    cfg(&mut regs);
    TCU::set_ep_regs(ep, &regs);
}

fn read_write(wr_addr: usize, rd_addr: usize, size: usize) {
    log!(
        crate::LOG_DEF,
        "WRITE to {:#x} and READ back into {:#x} with {} bytes",
        wr_addr,
        rd_addr,
        size
    );

    TCU::invalidate_tlb();

    let wr_slice = unsafe { util::slice_for_mut(wr_addr as *mut u8, size) };
    let rd_slice = unsafe { util::slice_for_mut(rd_addr as *mut u8, size) };

    // prepare test data
    for i in 0..size {
        wr_slice[i] = i as u8;
        rd_slice[i] = 0;
    }

    // configure mem EP
    config_local_ep(1, |regs| {
        TCU::config_mem(regs, OWN_VPE, PE::MEM.id(), 0x1000, size, Perm::RW);
    });

    // test write + read
    TCU::write(1, wr_slice.as_ptr(), size, 0).unwrap();
    TCU::read(1, rd_slice.as_mut_ptr(), size, 0).unwrap();

    assert_eq!(rd_slice, wr_slice);
}

fn test_mem(area_begin: usize, area_size: usize) {
    *XLATES.get_mut() = 0;
    let mut count = 0;

    let rd_area = area_begin;
    let wr_area = area_begin + area_size / 2;

    // same page
    {
        read_write(wr_area, wr_area + 16, 16);
        count += 1;
        assert_eq!(*XLATES, count);
    }

    // different pages, one page each
    {
        read_write(wr_area, rd_area, 16);
        count += 2;
        assert_eq!(*XLATES, count);
    }

    // unaligned
    {
        read_write(wr_area + 1, rd_area, 3);
        count += 2;
        assert_eq!(*XLATES, count);
    }
}

static RBUF1: [u64; 32] = [0; 32];
static RBUF2: [u64; 32] = [0; 32];

fn send_recv(send_addr: usize, size: usize) {
    let virt_to_phys = |virt: usize| -> (usize, ::paging::Phys) {
        let rbuf_pte = paging::translate(virt, PageFlags::R);
        (
            virt,
            (rbuf_pte & !cfg::PAGE_MASK as u64) + (virt & cfg::PAGE_MASK) as u64,
        )
    };

    let fetch_msg = |ep: EpId, rbuf: usize| -> Option<&'static Message> {
        tcu::TCU::fetch_msg(ep).map(|off| tcu::TCU::offset_to_msg(rbuf, off))
    };

    log!(
        crate::LOG_DEF,
        "SEND+REPLY from {:#x} with {} bytes",
        send_addr,
        size * 8
    );

    TCU::invalidate_tlb();

    // create receive buffers
    let (rbuf1_virt, rbuf1_phys) = virt_to_phys(RBUF1.as_ptr() as usize);
    let (rbuf2_virt, rbuf2_phys) = virt_to_phys(RBUF2.as_ptr() as usize);

    // create EPs
    let max_msg_ord = next_log2(16 + size * 8);
    assert!(RBUF1.len() * size_of::<u64>() >= 1 << max_msg_ord);
    config_local_ep(1, |regs| {
        TCU::config_recv(regs, OWN_VPE, rbuf1_phys, max_msg_ord, max_msg_ord, Some(2));
    });
    config_local_ep(3, |regs| {
        TCU::config_recv(regs, OWN_VPE, rbuf2_phys, max_msg_ord, max_msg_ord, None);
    });
    config_local_ep(4, |regs| {
        TCU::config_send(regs, OWN_VPE, 0x1234, PE::PE0.id(), 1, max_msg_ord, 1);
    });

    let msg_buf: &mut MsgBuf = unsafe { transmute(send_addr) };

    // prepare test data
    unsafe {
        for i in 0..size {
            msg_buf.words_mut()[i] = i as u64;
        }
        msg_buf.set_size(size * 8)
    };

    // send message
    TCU::send(4, &msg_buf, 0x1111, 3).unwrap();

    {
        // fetch message
        let rmsg = loop {
            if let Some(m) = fetch_msg(1, rbuf1_virt) {
                break m;
            }
        };
        assert_eq!({ rmsg.header.label }, 0x1234);
        let recv_slice =
            unsafe { util::slice_for(rmsg.data.as_ptr(), rmsg.header.length as usize) };
        assert_eq!(msg_buf.bytes(), recv_slice);

        // send reply
        TCU::reply(1, &msg_buf, tcu::TCU::msg_to_offset(rbuf1_virt, rmsg)).unwrap();
    }

    {
        // fetch reply
        let rmsg = loop {
            if let Some(m) = fetch_msg(3, rbuf2_virt) {
                break m;
            }
        };
        assert_eq!({ rmsg.header.label }, 0x1111);
        let recv_slice =
            unsafe { util::slice_for(rmsg.data.as_ptr(), rmsg.header.length as usize) };
        assert_eq!(msg_buf.bytes(), recv_slice);

        // ack reply
        tcu::TCU::ack_msg(3, tcu::TCU::msg_to_offset(rbuf2_virt, rmsg)).unwrap();
    }
}

fn test_msgs(area_begin: usize, _area_size: usize) {
    *XLATES.get_mut() = 0;
    let mut count = 0;

    // small
    {
        send_recv(area_begin, 1);
        count += 1;
        assert_eq!(*XLATES, count);
    }

    // large
    {
        send_recv(area_begin, 16);
        count += 1;
        assert_eq!(*XLATES, count);
    }
}

#[no_mangle]
pub extern "C" fn env_run() {
    io::init(0, "vmtest");

    log!(crate::LOG_DEF, "Setting up paging...");
    paging::init();

    log!(crate::LOG_DEF, "Setting up interrupts...");
    STATE.set(isr::State::default());
    isr::init(STATE.get_mut());
    isr::init_pexcalls(pexcall);
    isr::reg(isr::Vector::INSTR_PAGEFAULT.val, mmu_pf);
    isr::reg(isr::Vector::LOAD_PAGEFAULT.val, mmu_pf);
    isr::reg(isr::Vector::STORE_PAGEFAULT.val, mmu_pf);
    isr::reg(isr::Vector::SUPER_SW_IRQ.val, sw_irq);
    isr::reg(isr::Vector::MACH_TIMER_IRQ.val, timer_irq);
    isr::enable_irqs();

    log!(crate::LOG_DEF, "Triggering software IRQ...");
    write_csr!("sip", 0x2);

    let virt = cfg::ENV_START;
    let pte = paging::translate(virt, PageFlags::R);
    log!(
        crate::LOG_DEF,
        "Translated virt={:#x} to PTE={:#x}",
        virt,
        pte
    );

    log!(crate::LOG_DEF, "Mapping memory area...");
    let area_begin = 0xC100_0000;
    let area_size = cfg::PAGE_SIZE * 8;
    paging::map_anon(area_begin, area_size, PageFlags::RW).expect("Unable to map memory");

    test_mem(area_begin, area_size);
    test_msgs(area_begin, area_size);

    log!(crate::LOG_DEF, "Shutting down");
    exit(0);
}
