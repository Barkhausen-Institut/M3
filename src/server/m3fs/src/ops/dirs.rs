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

use crate::data::{DirEntry, DirEntryIterator, INodeRef, InodeNo};
use crate::ops::{inodes, links};

use m3::errors::{Code, Error};
use m3::vfs::FileMode;

/// Returns the directory and filename part of the given path.
///
/// - split_path("/foo/bar.baz") == ("/foo", "bar.baz")
/// - split_path("/foo/bar/") == ("/foo", "bar");
/// - split_path("foo") == ("", "foo");
fn split_path(mut path: &str) -> (&str, &str) {
    // skip trailing slashes
    while path.ends_with('/') {
        path = &path[..path.len() - 1];
    }

    let last_slash = path.rfind('/');
    if let Some(s) = last_slash {
        (&path[..s], &path[s + 1..])
    }
    else {
        // the path is either empty or only contained slashes
        ("", path)
    }
}

fn find_entry(inode: &INodeRef, name: &str) -> Result<InodeNo, Error> {
    if !inode.mode.is_dir() {
        return Err(Error::new(Code::IsNoDir));
    }

    log!(
        crate::LOG_FIND,
        "dirs::find(inode: {}, name={})",
        inode.inode,
        name
    );

    for ext in inode.extent_iter() {
        for block in ext.block_iter() {
            let entry_iter = DirEntryIterator::from_block(block.data());
            while let Some(entry) = entry_iter.next() {
                log!(crate::LOG_FIND, "  considering {}", entry.name());
                if entry.name() == name {
                    return Ok(entry.nodeno);
                }
            }
        }
    }

    Err(Error::new(Code::NoSuchFile))
}

/// Searches for the given path, optionally creates a new file, and returns the inode number.
pub fn search(path: &str, create: bool) -> Result<InodeNo, Error> {
    let ino = do_search(path, create);
    log!(
        crate::LOG_DIRS,
        "dirs::search(path={}, create={}) -> {:?}",
        path,
        create,
        ino.as_ref().map_err(|e| e.code()),
    );
    ino
}

fn do_search(mut path: &str, create: bool) -> Result<InodeNo, Error> {
    // remove all leading /
    while path.starts_with('/') {
        path = &path[1..];
    }

    // root inode?
    if path.is_empty() {
        return Ok(0);
    }

    // start at root inode with search
    let mut ino = 0;

    let (filename, inode) = loop {
        // get directory inode
        let inode = inodes::get(ino)?;

        // find directory entry
        let next_end = path.find('/').unwrap_or(path.len());
        let filename = &path[..next_end];
        let next_ino = find_entry(&inode, filename);

        // walk to next path component start
        let mut end = &path[next_end..];
        while end.starts_with('/') {
            end = &end[1..];
        }

        match next_ino {
            Ok(nodeno) => {
                // if path is now empty, finish searching
                if end.is_empty() {
                    return Ok(nodeno);
                }
                // continue with this directory
                ino = nodeno;
            },
            Err(e) if e.code() == Code::NoSuchFile => {
                // cannot create new file if it's not the last path component
                if !end.is_empty() {
                    return Err(Error::new(Code::NoSuchFile));
                }

                // not found, maybe we want to create it
                break (filename, inode);
            },
            Err(e) => return Err(e),
        }

        // to next path component
        path = end;
    };

    if create {
        // create inode and put link into directory
        let new_inode = inodes::create(FileMode::FILE_DEF)?;
        if let Err(e) = links::create(&inode, filename, &new_inode) {
            crate::open_files_mut().delete_file(new_inode.inode).ok();
            return Err(e);
        };
        return Ok(new_inode.inode);
    }

    Err(Error::new(Code::NoSuchFile))
}

/// Creates a new directory with given mode at given path
pub fn create(path: &str, mode: FileMode) -> Result<(), Error> {
    let res = do_create(path, mode);
    log!(
        crate::LOG_DIRS,
        "dirs::create(path={}, mode={:o}) -> {:?}",
        path,
        mode,
        res.as_ref().map_err(|e| e.code()),
    );
    res
}

fn do_create(path: &str, mode: FileMode) -> Result<(), Error> {
    let (dir, name) = split_path(path);

    // get parent directory
    let parent_ino = search(dir, false)?;

    // ensure that the entry doesn't exist
    if search(path, false).is_ok() {
        return Err(Error::new(Code::Exists));
    }

    let parinode = inodes::get(parent_ino)?;
    if let Ok(dirino) = inodes::create(FileMode::DIR_DEF | mode) {
        // create directory itself
        if let Err(e) = links::create(&parinode, name, &dirino) {
            crate::open_files_mut().delete_file(dirino.inode).ok();
            return Err(e);
        }

        // create "." link
        if let Err(e) = links::create(&dirino, ".", &dirino) {
            links::remove(&parinode, name, false).unwrap();
            return Err(e);
        }

        // create ".." link
        if let Err(e) = links::create(&dirino, "..", &parinode) {
            links::remove(&dirino, ".", false).unwrap();
            links::remove(&parinode, name, false).unwrap();
            return Err(e);
        }

        Ok(())
    }
    else {
        Err(Error::new(Code::NoSpace))
    }
}

/// Removes the directory at given path if it is empty
pub fn remove(path: &str) -> Result<(), Error> {
    log!(crate::LOG_DIRS, "dirs::remove(path={})", path);

    let ino = search(path, false)?;
    // cannot remove root directory
    if ino == 0 {
        return Err(Error::new(Code::InvArgs));
    }

    // it has to be a directory
    let inode = inodes::get(ino)?;
    if !inode.mode.is_dir() {
        return Err(Error::new(Code::IsNoDir));
    }

    // check whether it's empty
    for ext in inode.extent_iter() {
        for block in ext.block_iter() {
            let entry_iter = DirEntryIterator::from_block(block.data());
            while let Some(entry) = entry_iter.next() {
                if entry.name() != "." && entry.name() != ".." {
                    return Err(Error::new(Code::DirNotEmpty));
                }
            }
        }
    }

    // hardlinks to directories are not possible, thus we always have 2 ( . and ..)
    assert!(inode.links == 2, "expected 2 links, found {}", inode.links);

    let parent_inode = unlink(path, false)?;

    // we have already removed the entry; if something fails now we're screwed
    inodes::decrease_links(&parent_inode).unwrap();
    inodes::decrease_links(&inode).unwrap();

    Ok(())
}

/// Creates a link at `new_path` to `old_path`
pub fn link(old_path: &str, new_path: &str) -> Result<(), Error> {
    log!(
        crate::LOG_DIRS,
        "dirs::link(old_path={}, new_path={})",
        old_path,
        new_path
    );

    let old_ino = search(old_path, false)?;

    // it can't be a directory
    let old_inode = inodes::get(old_ino)?;
    if old_inode.mode.is_dir() {
        return Err(Error::new(Code::IsDir));
    }

    let (dir, name) = split_path(new_path);

    let base_ino = search(dir, false)?;
    let base_inode = inodes::get(base_ino)?;

    // the destination cannot already exist
    if find_entry(&base_inode, name).is_ok() {
        return Err(Error::new(Code::Exists));
    }

    links::create(&base_inode, name, &old_inode)
}

/// Removes the directory entry at given path
///
/// If `deny_dir` is true and the path points to a directory, the call fails.
///
/// Returns the directory inode
pub fn unlink(path: &str, deny_dir: bool) -> Result<INodeRef, Error> {
    log!(
        crate::LOG_DIRS,
        "dirs::unlink(path={}, deny_dir={})",
        path,
        deny_dir
    );

    let (dir, name) = split_path(path);
    // can't remove empty entries and internal entries
    if name.is_empty() || name == "." || name == ".." {
        return Err(Error::new(Code::InvArgs));
    }

    let par_ino = search(dir, false)?;
    let par_inode = inodes::get(par_ino)?;

    links::remove(&par_inode, name, deny_dir).map(|_| par_inode)
}

/// Renames `old_path` to `new_path`
pub fn rename(old_path: &str, new_path: &str) -> Result<(), Error> {
    log!(
        crate::LOG_DIRS,
        "dirs::rename(old_path={}, new_path={})",
        old_path,
        new_path
    );

    // split old path and get directory inode
    let (old_dir, old_name) = split_path(old_path);
    // cannot rename root directory or internal entries
    if old_name.is_empty() || old_name == "." || old_name == ".." {
        return Err(Error::new(Code::InvArgs));
    }
    let old_dir_ino = search(old_dir, false)?;
    let old_dir_inode = inodes::get(old_dir_ino)?;

    // get old inode to link to
    let old_ino = find_entry(&old_dir_inode, old_name)?;

    // renaming directories is not supported atm (we would need to change ".." as well)
    let old_inode = inodes::get(old_ino)?;
    if old_inode.mode.is_dir() {
        return Err(Error::new(Code::IsDir));
    }

    // find new path
    let (new_dir, new_name) = split_path(new_path);
    // cannot rename into root directory or internal entries
    if new_name.is_empty() || new_name == "." || new_name == ".." {
        return Err(Error::new(Code::InvArgs));
    }
    let new_dir_ino = search(new_dir, false)?;
    let new_dir_inode = inodes::get(new_dir_ino)?;

    // search for the entry in the new directory and change link to new inode if found
    let mut prev_ino = None;
    'search_loop: for ext in new_dir_inode.extent_iter() {
        for mut block in ext.block_iter() {
            let mut off = 0;
            let end = crate::superblock().block_size as usize;
            while off < end {
                // TODO marking all blocks dirty here is suboptimal
                let entry = DirEntry::from_buffer_mut(&mut block, off);
                if entry.name() == new_name {
                    // both link to the same inode? nothing to do
                    if entry.nodeno == old_ino {
                        return Ok(());
                    }

                    // remember original link
                    prev_ino = Some(entry.nodeno);

                    // set new inode
                    entry.nodeno = old_ino;
                    break 'search_loop;
                }

                off += entry.next as usize;
            }
        }
    }

    // point of no return: we have changed the DirEntry; for simplicity, we assume here that
    // everything works fine, because we cannot undo that operation safely since that could fail as
    // well.

    if let Some(prev_ino) = prev_ino {
        let prev_inode = inodes::get(prev_ino).unwrap();
        inodes::decrease_links(&prev_inode).unwrap();

        // increase links for the old_inode, because we will increase it in links::create below as
        // well and if we don't links::remove might delete the inode.
        old_inode.as_mut().links += 1;
    }
    else {
        links::create(&new_dir_inode, new_name, &old_inode).unwrap();
    }

    links::remove(&old_dir_inode, old_name, true).unwrap();
    Ok(())
}
