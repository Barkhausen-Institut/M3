/*
 * Copyright (C) 2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019-2021 Nils Asmussen, Barkhausen Institut
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

use core::arch::asm;
use core::sync::atomic;

use crate::arch::CPUOps;
use crate::mem::VirtAddr;

/// Reads the value of the given control and status register (CSR), e.g., "cr0"
#[macro_export]
macro_rules! read_csr {
    ($reg_name:tt) => {{
        let res: usize;
        unsafe {
            asm!(
                concat!("mov {0}, ", $reg_name),
                out(reg) res,
                options(nostack, nomem),
            )
        };
        res
    }};
}

/// Writes `$val` to the given control and status register (CSR), e.g., "cr0"
#[macro_export]
macro_rules! write_csr {
    ($reg_name:tt, $val:expr) => {
        unsafe {
            asm!(
                concat!("mov ", $reg_name, ", {0}"),
                in(reg) $val,
                options(nostack, nomem),
            )
        };
    };
}

pub struct X86CPU {}

impl CPUOps for X86CPU {
    unsafe fn read8b(addr: *const u64) -> u64 {
        let res: u64;
        asm!(
            "mov {0}, [{1}]",
            out(reg) res,
            in(reg) addr as usize,
            options(nostack),
        );
        res
    }

    unsafe fn write8b(addr: *mut u64, val: u64) {
        asm!(
            "mov [{1}], {0}",
            in(reg) val,
            in(reg) addr as usize,
            options(nostack),
        );
    }

    fn memory_barrier() {
        atomic::fence(atomic::Ordering::SeqCst);
    }

    #[inline(always)]
    fn stack_pointer() -> VirtAddr {
        let res: usize;
        unsafe {
            asm!(
                "mov {0}, rsp",
                out(reg) res,
                options(nostack, nomem),
            )
        };
        VirtAddr::from(res)
    }

    #[inline(always)]
    fn base_pointer() -> VirtAddr {
        let res: usize;
        unsafe {
            asm!(
                "mov {0}, rbp",
                out(reg) res,
                options(nostack, nomem),
            )
        };
        VirtAddr::from(res)
    }

    unsafe fn backtrace_step(bp: VirtAddr, func: &mut VirtAddr) -> VirtAddr {
        let bp_ptr = bp.as_ptr::<usize>();
        *func = VirtAddr::from(*bp_ptr.offset(1));
        VirtAddr::from(*bp_ptr)
    }

    fn elapsed_cycles() -> u64 {
        let u: u32;
        let l: u32;
        unsafe {
            asm!(
                "rdtsc",
                out("rax") l,
                out("rdx") u,
                options(nostack, nomem),
            );
        }
        u64::from(u) << 32 | u64::from(l)
    }

    fn gem5_debug(msg: u64) -> u64 {
        let res: u64;
        unsafe {
            asm!(
                ".byte 0x0F, 0x04",
                ".word 0x63",
                out("rax") res,
                in("rdi") msg,
                options(nostack),
            );
        }
        res
    }
}
