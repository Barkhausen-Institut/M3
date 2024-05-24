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

//! Machine-specific functions

use crate::cfg;
use crate::env;
use crate::errors::Error;
use crate::tcu;

#[cfg(feature = "coverage")]
struct Gem5CovWriter(u64);

#[cfg(feature = "coverage")]
impl minicov::CoverageWriter for Gem5CovWriter {
    fn write(&mut self, data: &[u8]) -> Result<(), minicov::CoverageWriteError> {
        tcu::TCU::write_coverage(data, self.0);
        Ok(())
    }
}

#[cfg(not(feature = "linux"))]
extern "C" {
    pub fn gem5_writefile(src: *const u8, len: u64, offset: u64, file: u64);
    pub fn gem5_shutdown(delay: u64);
}

pub fn write_coverage(_act: u64) {
    #[cfg(feature = "coverage")]
    if env::boot().platform == env::Platform::Gem5 {
        // safety: the function is not thread-safe, but we are always single threaded.
        unsafe {
            minicov::capture_coverage(&mut Gem5CovWriter(_act)).unwrap();
        }
    }
}

pub fn write(buf: &[u8]) -> Result<usize, Error> {
    let amount = tcu::TCU::print(buf);
    #[cfg(all(feature = "linux", feature = "gem5"))]
    unsafe {
        libc::write(1, buf.as_ptr() as *const libc::c_void, buf.len())
    };
    #[cfg(not(feature = "linux"))]
    {
        use crate::cpu::{CPUOps, CPU};
        if env::boot().platform == env::Platform::Gem5 {
            unsafe {
                let file = b"stdout\0";
                // make sure the buffer is actually written before we call gem5_writefile
                // without this it might end up in the store buffer, where gem5 doesn't see it.
                // note that the fence is only effective together with the volatile reads below
                // because it just controls ordering of memory accesses and not instructions.
                CPU::memory_barrier();
                // touch the string first to cause a page fault, if required. gem5 assumes that it's mapped
                let _b = file.as_ptr().read_volatile();
                let _b = file.as_ptr().add(6).read_volatile();
                gem5_writefile(buf.as_ptr(), amount as u64, 0, file.as_ptr() as u64);
            }
        }
    }
    Ok(amount)
}

/// Flushes the cache
///
/// # Safety
///
/// The caller needs to ensure that cfg::TILE_MEM_BASE is mapped and readable. The area needs to be
/// at least 512 KiB large.
pub unsafe fn flush_cache() {
    // * 2 just to be sure (this code is also touching memory)
    #[cfg(any(feature = "hw", feature = "hw22", feature = "hw23"))]
    let (cacheline_size, cache_size) = (64, 512 * 1024 * 2);
    #[cfg(not(any(feature = "hw", feature = "hw22", feature = "hw23")))]
    let (cacheline_size, cache_size) = (64, (32 + 256) * 1024 * 2);

    // ensure that we replace all cachelines in cache
    let mut addr = cfg::TILE_MEM_BASE.as_ptr::<u64>();
    unsafe {
        let end = addr.add(cache_size / 8);
        while addr < end {
            let _val = addr.read_volatile();
            addr = addr.add(cacheline_size / 8);
        }
    }

    #[cfg(all(
        not(target_arch = "riscv32"),
        any(feature = "hw", feature = "hw22", feature = "hw23")
    ))]
    unsafe {
        core::arch::asm!("fence.i");
    }
}

pub fn shutdown() -> ! {
    if env::boot().platform == env::Platform::Gem5 {
        #[cfg(not(feature = "linux"))]
        unsafe {
            gem5_shutdown(0)
        };
    }
    else {
        #[cfg(target_arch = "riscv64")]
        unsafe {
            core::arch::asm!("1: j 1b")
        };
    }
    unreachable!();
}

