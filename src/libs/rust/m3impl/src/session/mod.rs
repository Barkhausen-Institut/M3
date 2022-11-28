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

//! Contains session-related abstractions.

mod clisession;
mod disk;
mod hash;
mod m3fs;
mod netmng;
mod pager;
mod pipe;
pub mod resmng;
pub mod sig;
mod srvsession;

pub use self::clisession::ClientSession;
pub use self::disk::{BlockNo, BlockRange, Disk, DiskOperation};
pub use self::hash::{HashInput, HashOp, HashOutput, HashSession};
pub use self::m3fs::M3FS;
pub use self::netmng::{NetworkManager, NetworkOp};
pub use self::pager::{MapFlags, Pager, PagerOp};
pub use self::pipe::{Pipe, PipeOperation, Pipes};
pub use self::resmng::ResMng;
pub use self::srvsession::ServerSession;
