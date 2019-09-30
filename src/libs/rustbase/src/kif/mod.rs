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

//! Contains the kernel interface definitions

mod cap;
mod pedesc;
mod perm;

pub mod boot;
pub mod kpexcalls;
pub mod service;
pub mod syscalls;
pub mod upcalls;

pub use self::cap::*;
pub use self::pedesc::*;
pub use self::perm::*;

use dtu;

/// Represents an invalid capability selector
pub const INVALID_SEL: CapSel = 0xFFFF;

pub const SEL_VPE: CapSel = 0;
pub const SEL_MEM: CapSel = 1;
pub const SEL_SYSC_SG: CapSel = 2;
pub const SEL_SYSC_RG: CapSel = 3;
pub const SEL_UPC_RG: CapSel = 4;
pub const SEL_DEF_RG: CapSel = 5;
pub const SEL_PG_SG: CapSel = 6;
pub const SEL_PG_RG: CapSel = 7;

/// The first selector for the endpoint capabilities
pub const FIRST_EP_SEL: CapSel = SEL_PG_RG + 1;

/// The first free selector
pub const FIRST_FREE_SEL: CapSel = FIRST_EP_SEL + (dtu::EP_COUNT - dtu::FIRST_FREE_EP) as CapSel;
