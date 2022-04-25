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

use core::fmt;

use crate::borrow::StringRef;
use crate::cap::Selector;
use crate::cell::RefCell;
use crate::col::{String, ToString, Vec};
use crate::errors::{Code, Error};
use crate::rc::Rc;
use crate::serialize::Source;
use crate::session::M3FS;
use crate::tiles::{ChildActivity, StateSerializer};
use crate::vfs::{FileSystem, VFS};

/// A reference to a file system.
pub type FSHandle = Rc<RefCell<dyn FileSystem>>;

/// Represents a mount point
pub struct MountPoint {
    path: String,
    fs: FSHandle,
}

impl MountPoint {
    /// Creates a new mount point for given path and file system.
    pub fn new(path: &str, fs: FSHandle) -> MountPoint {
        MountPoint {
            path: path.to_string(),
            fs,
        }
    }
}

/// The table of mount points.
#[derive(Default)]
pub struct MountTable {
    mounts: Vec<MountPoint>,
    next_id: usize,
}

impl MountTable {
    /// Allocates a new id for the next file system
    pub fn alloc_id(&mut self) -> usize {
        let res = self.next_id;
        self.next_id += 1;
        res
    }

    /// Adds a new mount point at given path and given file system to the table.
    pub fn add(&mut self, path: &str, fs: FSHandle) -> Result<(), Error> {
        if self.path_to_idx(path).is_some() {
            return Err(Error::new(Code::Exists));
        }

        let pos = self.insert_pos(path);
        // ensure that we don't reuse ids, even if this filesystem was added after unserialization
        self.next_id = self.next_id.max(fs.borrow().id());
        self.mounts.insert(pos, MountPoint::new(path, fs));
        Ok(())
    }

    /// Returns the file system mounted exactly at the given path.
    pub fn get_by_path(&self, path: &str) -> Option<FSHandle> {
        self.path_to_idx(path).map(|i| self.mounts[i].fs.clone())
    }

    /// Returns the mount point with id `mid`.
    pub fn get_by_id(&self, mid: usize) -> Option<FSHandle> {
        self.mounts
            .iter()
            .find(|mp| mp.fs.borrow().id() == mid)
            .map(|mp| mp.fs.clone())
    }

    /// Returns the mount path of the mount with given id
    pub fn path_of_id(&self, mid: usize) -> Option<&String> {
        self.mounts
            .iter()
            .find(|mp| mp.fs.borrow().id() == mid)
            .map(|mp| &mp.path)
    }

    /// Resolves the given path to the file system image and the offset of the mount point within
    /// the path. The given path is turned into an absolute path in case it's relative. The returned
    /// offset refers to the absolute path.
    pub fn resolve(&self, path: &mut StringRef<'_>) -> Result<(FSHandle, usize), Error> {
        if !path.starts_with('/') {
            path.set(VFS::cwd() + "/" + &*path);
        }

        for m in &self.mounts {
            if path.starts_with(m.path.as_str()) {
                return Ok((m.fs.clone(), m.path.len()));
            }
        }
        Err(Error::new(Code::NoSuchFile))
    }

    /// Removes the mount point at `path` from the table.
    pub fn remove(&mut self, path: &str) -> Result<(), Error> {
        match self.path_to_idx(path) {
            Some(i) => {
                self.mounts.remove(i);
                Ok(())
            },
            None => Err(Error::new(Code::NoSuchFile)),
        }
    }

    pub(crate) fn delegate(&self, act: &ChildActivity) -> Result<Selector, Error> {
        let mut max_sel = 0;
        let mounts = act.mounts().clone();
        for (_cpath, ppath) in &mounts {
            if let Some(fs) = self.get_by_path(ppath) {
                let sel = fs.borrow().delegate(act)?;
                max_sel = sel.max(max_sel);
            }
        }
        Ok(max_sel)
    }

    pub(crate) fn serialize(&self, map: &[(String, String)], s: &mut StateSerializer<'_>) {
        s.push_word(map.len() as u64);

        for (cpath, ppath) in map {
            if let Some(fs) = self.get_by_path(ppath) {
                let fs = fs.borrow();
                let fs_type = fs.fs_type();
                s.push_str(cpath);
                s.push_word(fs_type as u64);
                fs.serialize(s);
            }
        }
    }

    pub(crate) fn unserialize(s: &mut Source<'_>) -> MountTable {
        let mut mt = MountTable::default();

        let count = s.pop().unwrap();
        for _ in 0..count {
            let path: String = s.pop().unwrap();
            let fs_type: u8 = s.pop().unwrap();
            mt.add(&path, match fs_type {
                b'M' => M3FS::unserialize(s),
                _ => panic!("Unexpected fs type {}", fs_type),
            })
            .unwrap();
        }

        mt
    }

    fn path_to_idx(&self, path: &str) -> Option<usize> {
        // TODO support imperfect paths
        assert!(path.starts_with('/'));
        assert!(path.ends_with('/'));
        assert!(!path.contains(".."));

        for (i, m) in self.mounts.iter().enumerate() {
            if m.path == path {
                return Some(i);
            }
        }
        None
    }

    fn insert_pos(&self, path: &str) -> usize {
        let comp_count = Self::path_comps(path);
        for (i, m) in self.mounts.iter().enumerate() {
            let cnt = Self::path_comps(m.path.as_str());
            if comp_count > cnt {
                return i;
            }
        }
        self.mounts.len()
    }

    fn path_comps(path: &str) -> usize {
        let mut comp_count = path.chars().filter(|&c| c == '/').count();
        if !path.ends_with('/') {
            comp_count += 1;
        }
        comp_count
    }
}

impl fmt::Debug for MountTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "MountTable[")?;
        for m in self.mounts.iter() {
            writeln!(f, "  {} -> {:?}", m.path, m.fs.borrow())?;
        }
        write!(f, "]")
    }
}
