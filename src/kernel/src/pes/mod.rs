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

mod pemng;
mod pemux;
mod vpe;
mod vpemng;

pub use self::pemng::PEMng;
pub use self::pemux::PEMux;
pub use self::vpe::{State, INVAL_ID, KERNEL_ID, VPE, VPEFlags};
pub use self::vpemng::VPEMng;

pub fn init() {
    self::pemng::init();
    self::vpemng::init();
}

pub fn deinit() {
    self::vpemng::deinit();
}
