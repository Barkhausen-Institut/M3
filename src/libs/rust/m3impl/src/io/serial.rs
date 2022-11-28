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

use core::any::Any;

use crate::cap::Selector;

use crate::errors::Error;
use crate::io;
use crate::session::{HashInput, HashOutput};
use crate::tiles::ChildActivity;
use crate::vfs;

impl vfs::File for io::Serial {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn fd(&self) -> vfs::Fd {
        0
    }

    fn set_fd(&mut self, _fd: vfs::Fd) {
    }

    fn file_type(&self) -> u8 {
        b'S'
    }

    fn delegate(&self, _act: &ChildActivity) -> Result<Selector, Error> {
        // nothing to do
        Ok(0)
    }
}

impl vfs::Seek for io::Serial {
}

impl vfs::Map for io::Serial {
}

impl vfs::Hashed for io::Serial {
}

impl HashInput for io::Serial {
}

impl HashOutput for io::Serial {
}
