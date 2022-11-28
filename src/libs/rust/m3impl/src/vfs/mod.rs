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

//! The virtual file system.

mod bufio;
mod dir;
mod file;
mod fileref;
mod filesystem;
mod filetable;
mod genericfile;
mod indirpipe;
mod mounttable;
#[allow(clippy::module_inception)]
mod vfs;
mod waiter;

/// A device ID
pub type DevId = u8;
/// An inode ID
pub type INodeId = u32;
/// A block ID
pub type BlockId = u32;

pub use self::bufio::{BufReader, BufWriter};
pub use self::dir::{read_dir, DirEntry, ReadDir};
pub use self::file::{
    File, FileEvent, FileInfo, FileMode, Hashed, Map, OpenFlags, Seek, SeekMode, TMode,
};
pub use self::fileref::FileRef;
pub use self::filesystem::{FSOperation, FileSystem};
pub(crate) use self::filetable::INV_FD;
pub use self::filetable::{Fd, FileTable};
pub use self::genericfile::{GenFileOp, GenericFile};
pub use self::indirpipe::IndirectPipe;
pub use self::mounttable::{FSHandle, MountTable};
pub use self::waiter::FileWaiter;

#[allow(non_snake_case)]
pub mod VFS {
    pub use crate::vfs::vfs::*;
}

pub(crate) fn deinit() {
    filetable::deinit();
}
