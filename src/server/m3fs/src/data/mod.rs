/*
 * Copyright (C) 2020 Nils Asmussen, Barkhausen Institut
 * Copyright (C) 2019-2020, Tendsin Mende <tendsin@protonmail.com>
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

mod allocator;
mod bitmap;
mod direntry;
mod extent;
mod inode;
mod superblock;

pub use allocator::Allocator;
pub use direntry::{DirEntry, DirEntryIterator};
pub use extent::{ExtPos, Extent, ExtentCache, ExtentRef};
pub use inode::INodeRef;
pub use superblock::SuperBlock;

pub type BlockNo = m3::session::BlockNo;
pub type BlockRange = m3::session::BlockRange;
pub type Dev = u8;
pub type InodeNo = u32;
pub type Time = u32;

pub const INODE_DIR_COUNT: usize = 3;
pub const MAX_BLOCK_SIZE: u32 = 4096;
pub const NUM_INODE_BYTES: usize = 64;
pub const NUM_EXT_BYTES: usize = 8;
pub const DIR_ENTRY_LEN: usize = 12;
