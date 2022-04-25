/*
 * Copyright (C) 2020-2021 Nils Asmussen, Barkhausen Institut
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

use crate::buf::MetaBufferBlockRef;
use crate::data::{
    BlockNo, Dev, Extent, ExtentCache, ExtentRef, InodeNo, Time, INODE_DIR_COUNT, NUM_INODE_BYTES,
};
use crate::ops::inodes;

use base::const_assert;

use core::u32;

use m3::cell::Cell;
use m3::mem::size_of;
use m3::vfs::{FileInfo, FileMode};

/// Represents an INode as stored on disk.
#[repr(C)]
pub struct INode {
    pub devno: Dev,
    _pad: u8,
    pub links: u16,

    pub lastaccess: Time,
    pub lastmod: Time,
    pub extents: u32,

    pub inode: InodeNo,
    pub mode: FileMode,
    pub size: u64,

    pub direct: [Extent; INODE_DIR_COUNT], // direct entries
    pub indirect: BlockNo,                 // location of the indirect block if != 0,
    pub dindirect: BlockNo,                // location of double indirect block if != 0
}

impl Clone for INode {
    fn clone(&self) -> Self {
        const_assert!(size_of::<INode>() == NUM_INODE_BYTES);
        INode {
            devno: self.devno,
            links: self.links,
            _pad: 0,

            inode: self.inode,
            mode: self.mode,
            size: self.size,

            lastaccess: self.lastaccess,
            lastmod: self.lastmod,
            extents: self.extents,

            direct: self.direct,
            indirect: self.indirect,
            dindirect: self.dindirect,
        }
    }
}

impl INode {
    pub fn reset(&mut self) {
        self.devno = 0;
        self.links = 0;
        self.inode = 0;
        self.mode = FileMode::empty();
        self.size = 0;
        self.lastaccess = 0;
        self.lastmod = 0;
        self.extents = 0;

        self.direct = [Extent {
            start: 0,
            length: 0,
        }; INODE_DIR_COUNT];
        self.indirect = 0;
        self.dindirect = 0;
    }

    pub fn to_file_info(&self) -> FileInfo {
        FileInfo {
            devno: self.devno,
            inode: self.inode,
            mode: self.mode,
            links: self.links as u32,
            size: self.size as usize,
            lastaccess: self.lastaccess,
            lastmod: self.lastmod,
            extents: self.extents as u32,
            blocksize: crate::superblock().block_size as u32,
            firstblock: self.direct[0].start,
        }
    }
}

/// A reference to an inode within a loaded MetaBuffer block.
pub struct INodeRef {
    block_ref: MetaBufferBlockRef,
    // this pointer is valid during our lifetime, because we keep a MetaBufferBlockRef
    inode: *mut INode,
    dirty: Cell<bool>,
}

impl INodeRef {
    pub fn from_buffer(block_ref: MetaBufferBlockRef, off: usize) -> Self {
        let block = crate::meta_buffer_mut().get_block_by_ref(&block_ref);

        // ensure that the offset is valid
        debug_assert!(
            (off % size_of::<INode>()) == 0,
            "INode offset {} is not multiple of INode size",
            off
        );
        debug_assert!(
            (off + size_of::<INode>()) <= block.data().len(),
            "INode at offset {} not within block",
            off,
        );

        // cast to inode at that offset within the block
        // safety: if the checks above succeeded, this cast is valid
        let inode = unsafe {
            let inode_ptr = block.data_mut().as_mut_ptr().cast::<INode>();
            inode_ptr.add(off / size_of::<INode>())
        };

        Self {
            block_ref,
            inode,
            dirty: Cell::from(false),
        }
    }

    pub fn extent_iter(&self) -> ExtentIterator<'_> {
        ExtentIterator {
            inode: self,
            indir: None,
            extno: 0,
        }
    }

    pub fn block(&self) -> &MetaBufferBlockRef {
        &self.block_ref
    }

    #[allow(clippy::mut_from_ref)]
    pub fn as_mut(&self) -> &mut INode {
        self.dirty.set(true);
        // safety: valid because we keep a MetaBufferBlockRef
        unsafe { &mut *self.inode }
    }
}

impl core::ops::Deref for INodeRef {
    type Target = INode;

    fn deref(&self) -> &Self::Target {
        // safety: valid because we keep a MetaBufferBlockRef
        unsafe { &*self.inode }
    }
}

impl Clone for INodeRef {
    fn clone(&self) -> Self {
        Self {
            block_ref: self.block_ref.clone(),
            inode: self.inode,
            // we reference the same block; there is no need to mark it dirty twice
            dirty: Cell::from(false),
        }
    }
}

impl Drop for INodeRef {
    fn drop(&mut self) {
        if self.dirty.get() {
            self.block_ref.mark_dirty();
        }
    }
}

/// Extent iterator that delivers all extents of an inode.
pub struct ExtentIterator<'e> {
    inode: &'e INodeRef,
    indir: Option<ExtentCache>,
    extno: usize,
}

impl<'e> core::iter::Iterator for ExtentIterator<'e> {
    type Item = ExtentRef;

    fn next(&mut self) -> Option<Self::Item> {
        if self.extno < self.inode.extents as usize {
            self.extno += 1;
            inodes::get_extent(self.inode, self.extno - 1, &mut self.indir, false).ok()
        }
        else {
            None
        }
    }
}
