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

//! Contains server-related abstractions.

#[allow(clippy::module_inception)]
mod server;
mod sesscon;

pub use self::server::{Handler, Server};
pub use self::sesscon::{SessId, SessionContainer};

use dtu::DTU;
use errors::Error;

/// Executes the server loop, calling `func` in every iteration.
pub fn server_loop<F: FnMut() -> Result<(), Error>>(mut func: F) -> Result<(), Error> {
    loop {
        // we are not interested in the events here; just fetch them before the sleep
        DTU::fetch_events();

        DTU::sleep().ok();

        func()?;
    }
}
