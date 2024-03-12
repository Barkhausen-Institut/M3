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

#![allow(internal_features)]
#![feature(core_intrinsics)]
#![cfg_attr(not(feature = "linux"), no_std)]

#[macro_use]
pub mod io;
#[macro_use]
pub mod com;
#[macro_use]
pub mod chan;

pub mod net;

pub use base::{
    backtrace, borrow, boxed, build_vmsg, cell, cfg, col, cpu, crypto, elf, errors, format,
    function, impl_boxitem, kif, libc, log, mem, quota, rc, serde, serialize, sync, tcu, time,
    tmif, util, vec,
};

pub mod cap;
pub mod client;
#[cfg(not(feature = "linux"))]
pub mod compat;
pub mod env;
pub mod server;
pub mod syscalls;
#[macro_use]
pub mod test;
pub mod tiles;
pub mod vfs;

#[cfg(feature = "linux")]
pub use base::linux;
