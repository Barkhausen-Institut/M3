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

use base::const_assert;
use bitflags::bitflags;
use core::any::Any;
use core::fmt::Debug;
use num_enum::IntoPrimitive;
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::cap::Selector;
use crate::client::{HashInput, HashOutput, MapFlags, Pager};
use crate::col::String;
use crate::com::EP;
use crate::errors::{Code, Error};
use crate::io::{Read, Write};
use crate::kif;
use crate::mem::VirtAddr;
use crate::serialize::{Deserialize, M3Serializer, Serialize, VecSink};
use crate::tiles::ChildActivity;
use crate::vfs::{BlockId, DevId, Fd, INodeId};

/// The different seek modes
#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive, Serialize_repr, Deserialize_repr)]
#[repr(u32)]
pub enum SeekMode {
    /// Set the file position to given absolute offset
    Set,
    /// Set the file position relatively to the current position
    Cur,
    /// Set the file position to the end of the file
    End,
}

bitflags! {
    /// The flags to open files
    #[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[repr(C)]
    #[serde(crate = "base::serde")]
    pub struct OpenFlags : u32 {
        /// Opens the file for reading
        const R         = 0b0000_0001;
        /// Opens the file for writing
        const W         = 0b0000_0010;
        /// Opens the file for code execution
        const X         = 0b0000_0100;
        /// Truncates the file on open
        const TRUNC     = 0b0000_1000;
        /// Appends to the file
        const APPEND    = 0b0001_0000;
        /// Creates the file if it doesn't exist
        const CREATE    = 0b0010_0000;
        /// For benchmarking: only pretend to access the file's data
        const NODATA    = 0b0100_0000;
        /// Create a new file session
        const NEW_SESS  = 0b1000_0000;

        /// Opens the file for reading and writing
        const RW        = Self::R.bits() | Self::W.bits();
        /// Opens the file for reading and code execution
        const RX        = Self::R.bits() | Self::X.bits();
        /// Opens the file for reading, writing, and code execution
        const RWX       = Self::R.bits() | Self::W.bits() | Self::X.bits();
    }
}

impl From<OpenFlags> for kif::Perm {
    fn from(flags: OpenFlags) -> Self {
        const_assert!(OpenFlags::R.bits() == kif::Perm::R.bits());
        const_assert!(OpenFlags::W.bits() == kif::Perm::W.bits());
        const_assert!(OpenFlags::X.bits() == kif::Perm::X.bits());
        kif::Perm::from_bits_truncate((flags & OpenFlags::RWX).bits())
    }
}

bitflags! {
    /// The file mode (type and access permissions)
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[repr(C)]
    #[serde(crate = "base::serde")]
    pub struct FileMode : u16 {
        const IFMT      = 0o0160000;
        const IFLNK     = 0o0120000;
        const IFPIP     = 0o0110000;
        const IFREG     = 0o0100000;
        const IFBLK     = 0o0060000;
        const IFDIR     = 0o0040000;
        const IFCHR     = 0o0020000;
        const ISUID     = 0o0004000;
        const ISGID     = 0o0002000;
        const ISSTICKY  = 0o0001000;
        const IRWXU     = 0o0000700;
        const IRUSR     = 0o0000400;
        const IWUSR     = 0o0000200;
        const IXUSR     = 0o0000100;
        const IRWXG     = 0o0000070;
        const IRGRP     = 0o0000040;
        const IWGRP     = 0o0000020;
        const IXGRP     = 0o0000010;
        const IRWXO     = 0o0000007;
        const IROTH     = 0o0000004;
        const IWOTH     = 0o0000002;
        const IXOTH     = 0o0000001;

        const FILE_DEF  = Self::IFREG.bits() | 0o0644;
        const DIR_DEF   = Self::IFDIR.bits();
        const PERM      = 0o777;
    }
}

impl FileMode {
    /// Returns true if this file mode represents a directory
    pub fn is_dir(self) -> bool {
        (self & Self::IFMT) == Self::IFDIR
    }

    /// Returns true if this file mode represents a regular file
    pub fn is_reg(self) -> bool {
        (self & Self::IFMT) == Self::IFREG
    }
}

/// The file information that can be retrieved via [`VFS::stat`](crate::vfs::VFS::stat)
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[repr(C)]
#[serde(crate = "base::serde")]
pub struct FileInfo {
    pub devno: DevId,
    pub inode: INodeId,
    pub mode: FileMode,
    pub links: u32,
    pub size: usize,
    pub lastaccess: u32,
    pub lastmod: u32,
    pub blocksize: u32,
    // for debugging
    pub extents: u32,
    pub firstblock: BlockId,
}

bitflags! {
    /// The events that are supported for a [`File`]
    #[repr(C)]
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct FileEvent : u32 {
        /// Input is available, that is, data can be read from the file
        const INPUT         = 1;
        /// Output is available, that is, data can be written to the file
        const OUTPUT        = 2;
        /// A signal is available (see [`File::fetch_signal`])
        const SIGNAL        = 4;
    }
}

/// The different terminal modes
#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive, Serialize_repr, Deserialize_repr)]
#[repr(u32)]
pub enum TMode {
    /// No handling of control characters and no buffering; pass all read characters to the client
    Raw,
    /// Handle control characters and pass full lines to the client
    Cooked,
}

/// Trait for files
///
/// All files can be read, written, seeked and mapped into memory.
pub trait File: Read + Write + Seek + Map + Debug + HashInput + HashOutput {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Returns the file descriptor
    fn fd(&self) -> Fd;
    /// Sets the file descriptor
    fn set_fd(&mut self, fd: Fd);

    /// Returns the session selector, if any
    fn session(&self) -> Option<Selector> {
        None
    }

    /// Executes necessary actions on file removal
    ///
    /// Implementations of [`File`] can use this to perform final actions when the file is removed
    /// from the file table.
    fn remove(&mut self) {
    }

    /// Retrieves the file information
    fn stat(&self) -> Result<FileInfo, Error> {
        Err(Error::new(Code::NotSup))
    }

    /// Retrieves the absolute path for this file, including its mount point
    fn path(&self) -> Result<String, Error> {
        Err(Error::new(Code::NotSup))
    }

    /// Truncates the file to the given length
    fn truncate(&mut self, _length: usize) -> Result<(), Error> {
        Err(Error::new(Code::NotSup))
    }

    /// Returns the current terminal mode in case the server is a terminal
    fn get_tmode(&self) -> Result<TMode, Error> {
        Err(Error::new(Code::NotSup))
    }

    /// Returns the type of the file implementation used for serialization
    fn file_type(&self) -> u8;
    /// Delegates this file to `act`
    fn delegate(&self, _act: &ChildActivity) -> Result<Selector, Error> {
        Err(Error::new(Code::NotSup))
    }
    /// Serializes this file into `s`
    fn serialize(&self, _s: &mut M3Serializer<VecSink<'_>>) {
    }

    /// Returns true if this file is operating in non-blocking mode (see
    /// [`set_blocking`](Self::set_blocking))
    fn is_blocking(&self) -> bool {
        true
    }

    /// Sets whether this file operates in blocking or non-blocking mode
    ///
    /// In blocking mode, [`read`](Read::read) and [`write`](Write::write) will block, whereas in
    /// non-blocking mode, they return [`Code::WouldBlock`] in case they would block (e.g., when the
    /// server needs to be asked to get access to the next input/output region).
    ///
    /// Note that setting the file to non-blocking might establish an additional communication
    /// channel to the server, if required and not already done.
    ///
    /// If the server or the file type does not the non-blocking mode, the [`Code::NotSup`] error is
    /// returned.
    fn set_blocking(&mut self, blocking: bool) -> Result<(), Error> {
        match blocking {
            true => Ok(()),
            false => Err(Error::new(Code::NotSup)),
        }
    }

    /// Tries to fetch a signal from the file, if any
    ///
    /// Note that this might establish an additional communication channel to the server, if
    /// required and not already done.
    ///
    /// If the server or the file type does not support signals, the [`Code::NotSup`] error is
    /// returned.
    ///
    /// Returns true if a signal was found
    fn fetch_signal(&mut self) -> Result<bool, Error> {
        Err(Error::new(Code::NotSup))
    }

    /// Checks whether any of the given events has arrived
    ///
    /// More specifically, if [`FileEvent::INPUT`] is given and reading from the file might result
    /// in receiving data, the function returns true.
    ///
    /// This function is used by the [`FileWaiter`](crate::vfs::FileWaiter) that waits until any of
    /// its files can make progress. Some types of files (e.g., sockets) needs to be "ticked" in
    /// each iteration to actually fetch such events. For other types of files, we can just retry
    /// read/write.
    fn check_events(&mut self, _events: FileEvent) -> bool {
        // by default, files are in blocking mode and therefore we always want to try read/write.
        true
    }

    /// Attaches this file to given send endpoint and memory endpoint.
    ///
    /// This method is intended to provide accelerators access to this file.
    fn attach(&mut self, _sep: EP, _mep: &EP) -> Result<(), Error> {
        Err(Error::new(Code::NotSup))
    }
}

/// Trait for resources that are seekable
pub trait Seek {
    /// Seeks to position `off`, using the given seek mode
    ///
    /// If `whence` == [`SeekMode::Set`], the position is set to `off`.
    /// If `whence` == [`SeekMode::Cur`], the position is increased by `off`.
    /// If `whence` == [`SeekMode::End`], the position is set to the end of the file.
    fn seek(&mut self, _off: usize, _whence: SeekMode) -> Result<usize, Error> {
        Err(Error::new(Code::NotSup))
    }
}

/// Trait for resources that can be mapped into the virtual address space
pub trait Map {
    /// Maps the region `off`..`off`+`len` of this file at address `virt` using the given pager and
    /// permissions
    fn map(
        &self,
        _pager: &Pager,
        _virt: VirtAddr,
        _off: usize,
        _len: usize,
        _prot: kif::Perm,
        _flags: MapFlags,
    ) -> Result<(), Error> {
        Err(Error::new(Code::NotSup))
    }
}
