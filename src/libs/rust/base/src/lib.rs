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

#![feature(alloc_error_handler, allocator_internals)]
#![feature(core_intrinsics)]
#![feature(maybe_uninit_write_slice)]
#![feature(lang_items)]
#![feature(panic_info_message)]
#![default_lib_allocator]
#![no_std]

extern crate alloc;
pub extern crate core as _core;

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(not(target_vendor = "host"))] {
        /// The C library
        pub mod libc {
            pub use crate::arch::libc::*;
        }
    }
    else {
        /// The C library
        pub extern crate libc;
    }
}

// Macros
pub use alloc::{format, vec};
pub use static_assertions::const_assert;

// lang stuff
mod lang;
pub use lang::*;

/// Pointer types for heap allocation
pub mod boxed {
    pub use alloc::boxed::Box;
}

/// Thread-safe reference-counting pointers
pub mod sync {
    pub use alloc::sync::{Arc, Weak};
}

#[macro_use]
pub mod io;
#[macro_use]
pub mod util;
#[macro_use]
pub mod test;

pub mod backtrace;
pub mod borrow;
pub mod cell;
pub mod col;
pub mod elf;
pub mod env;
pub mod errors;
pub mod kif;
pub mod math;
pub mod mem;
pub mod msgqueue;
pub mod parse;
pub mod quota;
pub mod random;
pub mod rc;
pub mod serialize;
pub mod time;
pub mod tmif;

mod arch;

/// An offset in a [`GlobAddr`](mem::GlobAddr)
#[allow(non_camel_case_types)]
pub type goff = u64;

/// Machine-specific functions
#[cfg(not(target_vendor = "host"))]
pub mod machine {
    pub use crate::arch::machine::*;
}

/// The target-dependent configuration
pub mod cfg {
    pub use crate::arch::cfg::*;
}
/// CPU-specific functions
pub mod cpu {
    pub use crate::arch::cpu::*;
}
/// The Trusted Communication Unit interface
pub mod tcu {
    pub use crate::arch::tcu::*;
}

/// The environment data
pub mod envdata {
    int_enum! {
        pub struct Platform : u64 {
            const GEM5 = 0;
            const HW = 1;
            const HOST = 2;
        }
    }

    pub use crate::arch::envdata::*;
}
