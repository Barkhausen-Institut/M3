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
use core::fmt;

use crate::boxed::Box;
use crate::cap::Selector;
use crate::errors::Error;
use crate::int_enum;
use crate::tiles::{ChildActivity, StateSerializer};
use crate::vfs::{File, FileInfo, FileMode, OpenFlags};

int_enum! {
    /// The file system operations.
    pub struct FSOperation : u64 {
        const STAT          = 14;
        const MKDIR         = 15;
        const RMDIR         = 16;
        const LINK          = 17;
        const UNLINK        = 18;
        const RENAME        = 19;
        const OPEN          = 20;
        const GET_SGATE     = 21;
        const GET_MEM       = 22;
        const DEL_EP        = 23;
        const OPEN_PRIV     = 24;
    }
}

/// Trait for file systems.
pub trait FileSystem: fmt::Debug {
    /// Returns an [`Any`] reference to downcast to the actual implementation of [`FileSystem`].
    fn as_any(&self) -> &dyn Any;

    /// Returns the id of this filesystem (within all local mounts)
    fn id(&self) -> usize;

    /// Opens the file at `path` with given flags.
    fn open(&mut self, path: &str, flags: OpenFlags) -> Result<Box<dyn File>, Error>;

    /// Closes the given file.
    fn close(&mut self, file_id: usize);

    /// Retrieves the file information for the file at `path`.
    fn stat(&self, path: &str) -> Result<FileInfo, Error>;

    /// Creates a new directory with given permissions at `path`.
    fn mkdir(&self, path: &str, mode: FileMode) -> Result<(), Error>;
    /// Removes the directory at `path`, if it is empty.
    fn rmdir(&self, path: &str) -> Result<(), Error>;

    /// Links `new_path` to `old_path`.
    fn link(&self, old_path: &str, new_path: &str) -> Result<(), Error>;
    /// Removes the file at `path`.
    fn unlink(&self, path: &str) -> Result<(), Error>;
    /// Renames `new_path` to `old_path`.
    fn rename(&self, old_path: &str, new_path: &str) -> Result<(), Error>;

    /// Returns the type of the file system implementation used for serialization.
    fn fs_type(&self) -> u8;
    /// Delegates this file system to `act`.
    fn delegate(&self, act: &ChildActivity) -> Result<Selector, Error>;
    /// Serializes this file system into `s`.
    fn serialize(&self, s: &mut StateSerializer<'_>);
}
