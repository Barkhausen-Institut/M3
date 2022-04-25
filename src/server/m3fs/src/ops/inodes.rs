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

use crate::buf::LoadLimit;
use crate::data::{
    ExtPos, Extent, ExtentCache, ExtentRef, INodeRef, InodeNo, INODE_DIR_COUNT, NUM_EXT_BYTES,
    NUM_INODE_BYTES,
};

use m3::{
    cap::Selector,
    com::Perm,
    errors::{Code, Error},
    math,
    vfs::{FileMode, SeekMode},
};

/// Creates a new inode with given mode and returns its INodeRef
pub fn create(mode: FileMode) -> Result<INodeRef, Error> {
    log!(crate::LOG_INODES, "inodes::create(mode={:o})", mode);

    let ino = crate::inodes_mut().alloc(None)?;
    let inode = get(ino)?;
    // reset inode
    inode.as_mut().reset();
    inode.as_mut().inode = ino;
    inode.as_mut().devno = 0; // TODO
    inode.as_mut().mode = mode;
    Ok(inode)
}

/// Decreases the number of links for the given inode and deletes it, if there are no links anymore
pub fn decrease_links(inode: &INodeRef) -> Result<(), Error> {
    inode.as_mut().links -= 1;
    if inode.links == 0 {
        let ino = inode.inode;
        crate::open_files_mut().delete_file(ino)?;
    }
    Ok(())
}

/// Frees the inode with given number
pub fn free(inode_no: InodeNo) -> Result<(), Error> {
    log!(crate::LOG_INODES, "inodes::free(inode_no={})", inode_no);

    let ino = get(inode_no)?;
    let inodeno = ino.inode as usize;
    truncate(&ino, &ExtPos::new(0, 0))?;
    crate::inodes_mut().free(inodeno, 1)
}

/// Loads an INodeRef for given inode number
pub fn get(inode: InodeNo) -> Result<INodeRef, Error> {
    log!(crate::LOG_INODES, "inodes::get({})", inode);

    let inos_per_block = crate::superblock().inodes_per_block();
    let bno = crate::superblock().first_inode_block() + (inode / inos_per_block as u32);
    let block = crate::meta_buffer_mut().get_block(bno)?;

    let offset = (inode as usize % inos_per_block as usize) * NUM_INODE_BYTES as usize;
    Ok(INodeRef::from_buffer(block, offset))
}

/// Calculates the extent and the offset within the extent for the given seek operation.
///
/// `off` is the desired offset and `whence` defines the seek mode.
///
/// Returns the new file position and the extent position
pub fn get_seek_pos(
    inode: &INodeRef,
    mut off: usize,
    whence: SeekMode,
) -> Result<(usize, ExtPos), Error> {
    log!(
        crate::LOG_INODES,
        "inodes::seek(inode={}, off={}, whence={})",
        inode.inode,
        off,
        whence,
    );

    assert!(whence != SeekMode::CUR);

    let blocksize = crate::superblock().block_size as usize;
    let mut indir = None;

    // seeking to the end
    if whence == SeekMode::END {
        // TODO support off != 0
        assert!(off == 0);

        let mut extpos = ExtPos::new(inode.extents as usize, 0);

        // determine extent offset
        if extpos.ext > 0 {
            let ext = get_extent(inode, extpos.ext - 1, &mut indir, false)?;
            // ensure to stay within a block
            let unaligned = (inode.size as usize) % blocksize;
            if unaligned > 0 {
                extpos.ext -= 1;
                extpos.off = ((ext.length as usize) * blocksize) - (blocksize - unaligned);
            }
        }

        return Ok((inode.size as usize, extpos));
    }

    if off as u64 > inode.size {
        off = inode.size as usize;
    }

    // now search until we've found the extent covering the desired file position
    let mut pos = 0;
    for i in 0..inode.extents {
        let ext = get_extent(inode, i as usize, &mut indir, false)?;

        if off < (ext.length as usize) * blocksize {
            return Ok((pos + off, ExtPos::new(i as usize, off)));
        }

        pos += ext.length as usize * blocksize;
        off -= ext.length as usize * blocksize;
    }

    Ok((pos + off, ExtPos::new(inode.extents as usize, off)))
}

/// Retrieves the memory beginning at the given position as a MemGate.
///
/// `pos` denotes the start position for the to-be-created MemGate, `perm` the permissions with
/// which the MemGate should be created, `sel` the selector for the MemGate, and `accessed` denotes
/// the number of times we already accessed this file.
///
/// Returns the length of the MemGate and the length of the extent
pub fn get_extent_mem(
    inode: &INodeRef,
    start: &ExtPos,
    perms: Perm,
    sel: Selector,
    limit: &mut LoadLimit,
) -> Result<(usize, usize), Error> {
    log!(
        crate::LOG_INODES,
        "inodes::get_extent_mem(inode={}, start={:?})",
        inode.inode,
        start,
    );

    let mut indir = None;
    let ext = get_extent(inode, start.ext, &mut indir, false)?;
    if ext.length == 0 {
        return Ok((0, 0));
    }

    // create memory capability for extent
    let blocksize = crate::superblock().block_size;
    let mut extlen = (ext.length * blocksize) as usize;

    let mut bytes = crate::backend_mut().get_filedata(*ext, start.off, perms, sel, Some(limit))?;

    // stop at file end
    if (start.ext == (inode.extents - 1) as usize)
        && ((ext.length * blocksize) as usize <= (start.off + bytes))
    {
        let rem = (inode.size % blocksize as u64) as u32;
        if rem > 0 {
            bytes -= (blocksize - rem) as usize;
            extlen -= (blocksize - rem) as usize;
        }
    }

    Ok((bytes, extlen))
}

/// Requests an append of a new block to given inode and creates a MemGate to access the block.
///
/// Note that this only requests the append, but does not append anything.
///
/// `pos` denotes the position where to append to, `sel` the selector to use for the MemGate, `perm`
/// the permissions for the MemGate, and `accessed` denotes the number of times we already accessed
/// this file.
pub fn req_append(
    inode: &INodeRef,
    pos: &ExtPos,
    sel: Selector,
    perm: Perm,
    limit: &mut LoadLimit,
) -> Result<(usize, usize, Option<Extent>), Error> {
    let num_extents = inode.extents;

    log!(
        crate::LOG_INODES,
        "inodes::req_append(inode={}, pos={:?}, num_extents={})",
        inode.inode,
        pos,
        num_extents
    );

    if pos.ext < inode.extents as usize {
        let mut indir = None;
        let ext = get_extent(inode, pos.ext, &mut indir, false)?;

        let extlen = (ext.length * crate::superblock().block_size) as usize;
        let bytes = crate::backend_mut().get_filedata(*ext, pos.off, perm, sel, Some(limit))?;
        Ok((bytes, extlen, None))
    }
    else {
        let ext = create_extent(None, crate::settings().extend as u32)?;

        // this is a new extent we don't have to load it
        let load = if crate::settings().clear {
            Some(limit)
        }
        else {
            None
        };

        let extlen = (ext.length * crate::superblock().block_size) as usize;
        let bytes = crate::backend_mut().get_filedata(ext, 0, perm, sel, load)?;
        Ok((bytes, extlen, Some(ext)))
    }
}

/// Actually appends the given extent to the inode.
///
/// Returns whether a new extent was created (false means that it was appended to an existing one).
pub fn append_extent(inode: &INodeRef, next: Extent) -> Result<bool, Error> {
    log!(
        crate::LOG_INODES,
        "inodes::append_extent(inode={}, next=(start={}, length={}))",
        inode.inode,
        next.start,
        next.length,
    );

    let mut indir = None;
    let mut new_ext = true;

    // try to load existing inode
    let ext = if inode.extents > 0 {
        let ext = get_extent(inode, (inode.extents - 1) as usize, &mut indir, false)?;
        if ext.start + ext.length != next.start {
            None
        }
        else {
            new_ext = false;
            Some(ext)
        }
    }
    else {
        None
    };

    // if found, append to extent
    if let Some(ref ext) = ext {
        ext.as_mut().length += next.length;
    }
    // create new extent
    else {
        let ext = get_extent(inode, inode.extents as usize, &mut indir, true)?;
        inode.as_mut().extents += 1;

        *ext.as_mut() = next;
    }

    Ok(new_ext)
}

/// Requests the given extent from given inode.
///
/// `indir` denotes an ExtentCache to speed up loading of the indirect block with extents, and
/// `create` whether the extent should be created in case it does not exist.
///
/// Returns the ExtentRef
pub fn get_extent(
    inode: &INodeRef,
    mut extent: usize,
    indir: &mut Option<ExtentCache>,
    create: bool,
) -> Result<ExtentRef, Error> {
    log!(
        crate::LOG_INODES,
        "inodes::get_extent(inode={}, extent={}, create={})",
        inode.inode,
        extent,
        create
    );

    // direct extent stored in the inode?
    if extent < INODE_DIR_COUNT {
        return Ok(ExtentRef::dir_from_inode(inode, extent));
    }
    extent -= INODE_DIR_COUNT;

    let mb = crate::meta_buffer_mut();

    // indirect extent stored in the nodes indirect block?
    if extent < crate::superblock().extents_per_block() {
        // create indirect block if not done yet
        if indir.is_none() {
            let mut created = false;
            if inode.indirect == 0 {
                if !create {
                    return Err(Error::new(Code::NotFound));
                }
                // alloc block for indirect extents and put in inode
                let indirect_block = crate::blocks_mut().alloc(None)?;
                inode.as_mut().indirect = indirect_block;
                created = true;
            }

            // load block and initialize extents
            let mut data_ref = mb.get_block(inode.indirect)?;
            if created {
                data_ref.overwrite_zero();
            }

            // create extent cache from that block
            *indir = Some(ExtentCache::from_buffer(data_ref));
        }

        return Ok(indir.as_ref().unwrap().get_ref(extent));
    }

    // double indirect extents
    let ext_per_block = crate::superblock().extents_per_block();
    extent -= ext_per_block;

    if extent < (ext_per_block * ext_per_block) {
        let mut created = false;
        // create double indirect block, if not done yet
        if inode.dindirect == 0 {
            if !create {
                return Err(Error::new(Code::NotFound));
            }
            let dindirect_block = crate::blocks_mut().alloc(None)?;
            inode.as_mut().dindirect = dindirect_block;
            created = true;
        }

        // init with zeros
        let mut dind_block_ref = mb.get_block(inode.dindirect)?;
        if created {
            dind_block_ref.overwrite_zero();
        }

        log!(
            crate::LOG_INODES,
            "Using d-indirect block, WARNING: not fully tested atm."
        );

        // create indirect block if necessary
        created = false;
        let ptr = ExtentRef::indir_from_buffer(
            dind_block_ref,
            (extent / crate::superblock().extents_per_block()) * NUM_EXT_BYTES,
        );
        if ptr.length == 0 {
            ptr.as_mut().start = crate::blocks_mut().alloc(None)?;
            ptr.as_mut().length = 1;
            created = true;
        }

        // init with zeros
        let mut ind_block_ref = mb.get_block(ptr.start)?;
        if created {
            ind_block_ref.overwrite_zero();
        }

        // get extent
        let ext = ExtentRef::indir_from_buffer(
            ind_block_ref,
            (extent % crate::superblock().extents_per_block()) * NUM_EXT_BYTES,
        );

        return Ok(ext);
    }

    // extent was not within the doubly indirect extents
    Err(Error::new(Code::NotFound))
}

/// Retrieves the given extent from given inode and removes it if requested.
///
/// Assumes that the extent exists.
///
/// `indir` denotes an ExtentCache to speed up loading of the indirect block with extents, and
/// `create` whether the extent should be created in case it does not exist.
///
/// Returns the ExtentRef
fn change_extent(
    inode: &INodeRef,
    mut extent: usize,
    indir: &mut Option<ExtentCache>,
    remove: bool,
) -> Result<ExtentRef, Error> {
    log!(
        crate::LOG_INODES,
        "inodes::change_extent(inode={}, extent={}, remove={})",
        inode.inode,
        extent,
        remove,
    );

    let ext_per_block = crate::superblock().extents_per_block();

    if extent < INODE_DIR_COUNT {
        return Ok(ExtentRef::dir_from_inode(inode, extent));
    }

    let mb = crate::meta_buffer_mut();

    extent -= INODE_DIR_COUNT;
    if extent < ext_per_block {
        assert!(inode.indirect != 0);

        // load indirect extent cache, if not done yet
        if indir.is_none() {
            let data_ref = mb.get_block(inode.indirect)?;
            *indir = Some(ExtentCache::from_buffer(data_ref));
        }

        // we assume that we only delete extents at the end; thus, if its the first, we can remove
        // the indirect block as well.
        if remove && extent == 0 {
            crate::blocks_mut().free(inode.indirect as usize, 1)?;
            inode.as_mut().indirect = 0;
        }

        return Ok(indir.as_ref().unwrap().get_ref(extent));
    }

    extent -= ext_per_block;
    if extent < (ext_per_block * ext_per_block) {
        assert!(inode.dindirect != 0);

        // load block with doubly indirect extents
        let data_ref = mb.get_block(inode.dindirect)?;
        let ptr = ExtentRef::indir_from_buffer(data_ref, (extent / ext_per_block) * NUM_EXT_BYTES);
        let dindir = mb.get_block(ptr.start)?;

        // load extent
        let ext_loc = (extent % ext_per_block) * NUM_EXT_BYTES;
        let ext = ExtentRef::indir_from_buffer(dindir, ext_loc);

        // same here: if its the first, remove the indirect, an maybe the indirect block
        if remove {
            // Is first block in dind block
            if ext_loc == 0 {
                crate::blocks_mut().free(ptr.start as usize, 1)?;
                ptr.as_mut().start = 0;
                ptr.as_mut().length = 0;
            }

            // for the double-indirect too
            if extent == 0 {
                crate::blocks_mut().free(inode.dindirect as usize, 1)?;
                inode.as_mut().dindirect = 0;
            }
        }

        return Ok(ext);
    }

    // extent was not within the doubly indirect extents
    Err(Error::new(Code::NotFound))
}

/// Creates a new extent for given inode with given number of blocks
///
/// `accessed` denotes the number of times we already accessed this file.
///
/// Returns the created extent
pub fn create_extent(inode: Option<&INodeRef>, blocks: u32) -> Result<Extent, Error> {
    let mut count = blocks as usize;
    let start = crate::blocks_mut().alloc(Some(&mut count))?;
    let ext = Extent::new(start, count as u32);

    let blocksize = crate::superblock().block_size;
    if crate::settings().clear {
        crate::backend_mut().clear_extent(ext)?;
    }

    if let Some(ino) = inode {
        let old_size = ino.size;
        ino.as_mut().extents += 1;
        ino.as_mut().size = (old_size + blocksize as u64 - 1) & !(blocksize as u64 - 1);
        ino.as_mut().size += (count * blocksize as usize) as u64;
    }

    Ok(ext)
}

/// Truncates the given inode until the given position.
pub fn truncate(inode: &INodeRef, pos: &ExtPos) -> Result<(), Error> {
    log!(
        crate::LOG_INODES,
        "inodes::truncate(inode={}, pos={:?})",
        inode.inode,
        pos,
    );

    let blocksize = crate::superblock().block_size;
    let mut indir = None;

    let iextents: usize = inode.extents as usize;

    if iextents > 0 {
        // erase everything up to `extent`
        let mut i = iextents - 1;
        while i > pos.ext {
            let ext = change_extent(inode, i, &mut indir, true)?;
            crate::blocks_mut().free(ext.start as usize, ext.length as usize)?;
            inode.as_mut().extents -= 1;
            inode.as_mut().size -= (ext.length * blocksize) as u64;
            ext.as_mut().start = 0;
            ext.as_mut().length = 0;
            i -= 1;
        }

        // get `extent` and determine length
        let ext = change_extent(inode, pos.ext, &mut indir, pos.off == 0)?;
        if ext.length > 0 {
            let mut curlen = ext.length * blocksize;

            let modul = inode.size % blocksize as u64;
            if modul != 0 {
                curlen -= blocksize - modul as u32;
            }

            // do we need to reduce the size of `extent`?
            if pos.off < curlen as usize {
                let diff = curlen as usize - pos.off;
                let bdiff = if pos.off == 0 {
                    math::round_up(diff, blocksize as usize)
                }
                else {
                    diff
                };
                let blocks = bdiff / blocksize as usize;
                if blocks > 0 {
                    // free all of these blocks
                    crate::blocks_mut().free((ext.start + ext.length) as usize - blocks, blocks)?;
                }
                inode.as_mut().size -= diff as u64;
                ext.as_mut().length = (ext.length as usize - blocks) as u32;
                if ext.length == 0 {
                    ext.as_mut().start = 0;
                    inode.as_mut().extents -= 1;
                }
            }
        }
    }

    Ok(())
}

/// Writes all dirty metadata from given inode back to storage
pub fn sync_metadata(inode: &INodeRef) -> Result<(), Error> {
    log!(
        crate::LOG_INODES,
        "inodes::sync_metadata(inode={})",
        inode.inode,
    );

    for ext in inode.extent_iter() {
        for mut block in ext.block_iter() {
            crate::backend_mut().sync_meta(&mut block)?;
            block.flush()?;
        }
    }
    Ok(())
}
