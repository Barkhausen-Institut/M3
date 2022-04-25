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

use crate::borrow::StringRef;
use crate::col::{String, ToString};
use crate::env;
use crate::errors::{Code, Error};
use crate::rc::Rc;
use crate::session::M3FS;
use crate::tiles::Activity;
use crate::vfs::{FSHandle, File, FileInfo, FileMode, FileRef, GenericFile, OpenFlags};

/// Mounts the file system of type `fstype` at `path`, creating a session at `service`.
pub fn mount(path: &str, fstype: &str, service: &str) -> Result<(), Error> {
    let id = Activity::own().mounts().alloc_id();
    let fsobj = match fstype {
        "m3fs" => M3FS::new(id, service)?,
        _ => return Err(Error::new(Code::InvArgs)),
    };
    Activity::own().mounts().add(path, fsobj)
}

/// Umounts the file system mounted at `path`.
pub fn unmount(path: &str) -> Result<(), Error> {
    Activity::own().mounts().remove(path)
}

fn with_path<F, R>(path: &str, func: F) -> Result<R, Error>
where
    F: Fn(&FSHandle, &str) -> Result<R, Error>,
{
    let mut path = StringRef::Borrowed(path);
    let (fs, pos) = Activity::own().mounts().resolve(&mut path)?;
    func(&fs, &path[pos..])
}

/// Creates an absolute and canonical path from given path
///
/// That is, duplicate slashes are removed and '.' and '..' are removed accordingly. Additionally,
/// `cwd` is prepended if the path is not absolute.
pub fn abs_path(path: &str) -> String {
    let mut canon = canon_path(path);
    // make it absolute
    if !path.starts_with("/") {
        let mut cwd = cwd();
        if !cwd.ends_with("/") && !canon.is_empty() {
            cwd.push('/');
        }
        canon.insert_str(0, &cwd);
    }
    canon
}

/// Creates a canonical path from the given path
///
/// That is, duplicate slashes are removed and '.' and '..' are removed accordingly.
pub fn canon_path(path: &str) -> String {
    let mut res = String::new();
    let mut begin = 0;

    if path.starts_with("/") {
        res.push('/');
        begin += 1;
    }

    for c in path.split('/') {
        if c == "." {
            // do nothing
        }
        else if c == ".." {
            // remove last component
            while res.len() > begin && !res.ends_with("/") {
                res.remove(res.len() - 1);
            }
            // remove last slash
            if res.len() > begin {
                res.remove(res.len() - 1);
            }
        }
        else if !c.is_empty() {
            // add new component
            if res.len() > begin {
                res.push('/');
            }
            res.push_str(c);
        }
    }

    res
}

/// Returns the current working directory
pub fn cwd() -> String {
    env::var("PWD").unwrap_or("/".to_string())
}

/// Sets the current working directory to given path
pub fn set_cwd(path: &str) -> Result<(), Error> {
    let file = open(path, OpenFlags::R)?;
    let info = file.stat()?;
    if !info.mode.is_dir() {
        return Err(Error::new(Code::IsNoDir));
    }

    env::set_var("PWD", abs_path(path));
    Ok(())
}

/// Opens the file at `path` with given flags.
pub fn open(path: &str, flags: OpenFlags) -> Result<FileRef<GenericFile>, Error> {
    with_path(path, |fs, fs_path| {
        let file = fs.borrow_mut().open(fs_path, flags)?;
        let fd = Activity::own().files().add(file)?;
        Ok(FileRef::new_owned(fd))
    })
}

/// Retrieves the file information from the file at `path`.
pub fn stat(path: &str) -> Result<FileInfo, Error> {
    with_path(path, |fs, fs_path| fs.borrow().stat(fs_path))
}

/// Creates a directory with permissions `mode` at `path`.
pub fn mkdir(path: &str, mode: FileMode) -> Result<(), Error> {
    with_path(path, |fs, fs_path| fs.borrow().mkdir(fs_path, mode))
}

/// Removes the directory at `path`, if it is empty.
pub fn rmdir(path: &str) -> Result<(), Error> {
    with_path(path, |fs, fs_path| fs.borrow().rmdir(fs_path))
}

/// Creates a link at `new` to `old`.
pub fn link(old: &str, new: &str) -> Result<(), Error> {
    let mut old = StringRef::Borrowed(old);
    let (fs1, pos1) = Activity::own().mounts().resolve(&mut old)?;
    let mut new = StringRef::Borrowed(new);
    let (fs2, pos2) = Activity::own().mounts().resolve(&mut new)?;
    if !Rc::ptr_eq(&fs1, &fs2) {
        return Err(Error::new(Code::XfsLink));
    }
    #[allow(clippy::let_and_return)] // is required because of fs1.borrow()'s lifetime
    let res = fs1.borrow().link(&old[pos1..], &new[pos2..]);
    res
}

/// Removes the file at `path`.
pub fn unlink(path: &str) -> Result<(), Error> {
    with_path(path, |fs, fs_path| fs.borrow().unlink(fs_path))
}

/// Renames `new` to `old`.
pub fn rename(old: &str, new: &str) -> Result<(), Error> {
    let mut old = StringRef::Borrowed(old);
    let (fs1, pos1) = Activity::own().mounts().resolve(&mut old)?;
    let mut new = StringRef::Borrowed(new);
    let (fs2, pos2) = Activity::own().mounts().resolve(&mut new)?;
    if !Rc::ptr_eq(&fs1, &fs2) {
        return Err(Error::new(Code::XfsLink));
    }
    #[allow(clippy::let_and_return)] // is required because of fs1.borrow()'s lifetime
    let res = fs1.borrow().rename(&old[pos1..], &new[pos2..]);
    res
}
