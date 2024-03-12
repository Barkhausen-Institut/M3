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

use cfg_if::cfg_if;

use crate::errors::Error;
use crate::mem::VirtAddr;
use crate::tmif::Operation;

/// Contains CPU-specific operations
pub trait CPUOps {
    /// Reads 8 byte from the given address (using a single load)
    ///
    /// # Safety
    ///
    /// The function assumes that the address is 8-byte aligned and refers to accessible memory.
    unsafe fn read8b(addr: *const u64) -> u64;

    /// Writes `val` as an 8-byte value to the given address (using a single store)
    ///
    /// # Safety
    ///
    /// The function assumes that the address is 8-byte aligned and refers to accessible memory.
    unsafe fn write8b(addr: *mut u64, val: u64);

    /// Returns the stack pointer
    fn stack_pointer() -> VirtAddr;

    /// Returns the base pointer
    fn base_pointer() -> VirtAddr;

    /// Returns the number of elapsed cycles
    fn elapsed_cycles() -> u64;

    /// Architecture-specific helper function for the backtrace module
    ///
    /// Sets `func` to the base pointer stored at address `bp` and returns the address of the next base
    /// pointer.
    ///
    /// # Safety
    ///
    /// Assumes that `func` is usize-aligned and refers to accessible memory.
    unsafe fn backtrace_step(bp: VirtAddr, func: &mut VirtAddr) -> VirtAddr;

    /// Uses a special instruction to write the given "message" into the gem5 log
    fn gem5_debug(msg: u64) -> u64;
}

/// The TileMux ABI operations
pub trait TMABIOps {
    /// A TileMux call with a single argument
    #[allow(unused)]
    fn call1(op: Operation, arg1: usize) -> Result<(), Error>;

    /// A TileMux call with a two arguments
    #[allow(unused)]
    fn call2(op: Operation, arg1: usize, arg2: usize) -> Result<(), Error>;

    /// A TileMux call with a three arguments
    #[allow(unused)]
    fn call3(op: Operation, arg1: usize, arg2: usize, arg3: usize) -> Result<(), Error>;

    /// A TileMux call with a four arguments
    #[allow(unused)]
    fn call4(
        op: Operation,
        arg1: usize,
        arg2: usize,
        arg3: usize,
        arg4: usize,
    ) -> Result<(), Error>;
}

cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        #[path = "x86_64/mod.rs"]
        mod isa;

        pub type CPU = crate::arch::isa::cpu::X86CPU;
        #[cfg(not(feature = "linux"))]
        pub type TMABI = crate::arch::isa::tmabi::X86TMABI;
    }
    else if #[cfg(target_arch = "arm")] {
        #[path = "arm/mod.rs"]
        mod isa;

        pub type CPU = crate::arch::isa::cpu::ARMCPU;
        #[cfg(not(feature = "linux"))]
        pub type TMABI = crate::arch::isa::tmabi::ARMTMABI;
    }
    else {
        #[path = "riscv/mod.rs"]
        mod isa;

        pub type CPU = crate::arch::isa::cpu::RISCVCPU;
        #[cfg(not(feature = "linux"))]
        pub type TMABI = crate::arch::isa::tmabi::RISCVTMABI;
    }
}

#[cfg(feature = "linux")]
pub mod linux;
