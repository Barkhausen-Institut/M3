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

#[cfg(target_os = "none")]
#[path = "gem5/mod.rs"]
mod inner;

#[cfg(target_os = "linux")]
#[path = "host/mod.rs"]
mod inner;

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
mod isa;

#[cfg(target_arch = "arm")]
#[path = "arm/mod.rs"]
mod isa;

#[cfg(target_arch = "riscv64")]
#[path = "riscv/mod.rs"]
mod isa;

pub use self::inner::*;
pub use self::isa::*;

#[cfg(target_os = "none")]
pub(crate) fn get_result(res: isize) -> Result<usize, base::errors::Error> {
    match res {
        e if e < 0 => Err(base::errors::Error::from(-e as u32)),
        val => Ok(val as usize),
    }
}
