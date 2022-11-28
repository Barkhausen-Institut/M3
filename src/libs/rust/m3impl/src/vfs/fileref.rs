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
use core::marker::PhantomData;

use crate::cap::Selector;
use crate::cell::RefMut;
use crate::col::String;
use crate::errors::Error;
use crate::goff;
use crate::io::{Read, Write};
use crate::kif;
use crate::net::{DGramSocket, Socket, StreamSocket};
use crate::serialize::{M3Serializer, VecSink};
use crate::session::{HashInput, HashOutput, HashSession, MapFlags, Pager};
use crate::tiles::{Activity, ChildActivity};
use crate::vfs::{Fd, File, FileEvent, FileTable, Hashed, Map, Seek, SeekMode, TMode};

/// A file reference provides access to a file of type `T`.
///
/// Depending on whether `FileRef` was created via [`FileRef::new_owned`] or [`FileRef::new`] the
/// file is closed on drop or not, respectively.
#[derive(Clone)]
pub struct FileRef<T: ?Sized> {
    fd: Fd,
    close: bool,
    phantom: PhantomData<T>,
}

impl<T: ?Sized> FileRef<T> {
    /// Creates new file reference for the given file descriptor. The file is not closed on drop.
    pub fn new(fd: Fd) -> Self {
        FileRef {
            fd,
            close: false,
            phantom: PhantomData::default(),
        }
    }

    /// Creates new file reference for the given file descriptor. On drop, the file is closed.
    pub fn new_owned(fd: Fd) -> Self {
        FileRef {
            fd,
            close: true,
            phantom: PhantomData::default(),
        }
    }

    /// Claims the ownership of the file in the sense that this `FileRef` does not close the file on
    /// drop. Therefore, the caller is responsible to close the file.
    pub fn claim(&mut self) {
        self.close = false;
    }

    /// Returns the file descriptor.
    pub fn fd(&self) -> Fd {
        self.fd
    }

    /// Returns the file.
    pub fn borrow(&self) -> RefMut<'_, dyn File> {
        let files = Activity::own().files();
        FileTable::get_raw(files, self.fd).unwrap()
    }

    /// Converts this file reference into a generic one
    pub fn into_generic(mut self) -> FileRef<dyn File> {
        self.close = false;
        FileRef::new_owned(self.fd)
    }
}

impl<T: 'static> FileRef<T> {
    /// Returns the file.
    pub fn borrow_as(&self) -> RefMut<'_, T> {
        let files = Activity::own().files();
        let file = FileTable::get_raw(files, self.fd).unwrap();
        RefMut::map(file, |f| f.as_any_mut().downcast_mut().unwrap())
    }
}

impl<T: ?Sized> Drop for FileRef<T> {
    fn drop(&mut self) {
        if self.close {
            Activity::own().files().remove(self.fd);
        }
    }
}

impl<T: ?Sized + 'static> File for FileRef<T> {
    fn as_any(&self) -> &dyn Any {
        panic!("Cannot call as_any on a FileRef!");
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        panic!("Cannot call as_any_mut on a FileRef!");
    }

    fn fd(&self) -> Fd {
        self.fd
    }

    fn set_fd(&mut self, fd: Fd) {
        self.borrow().set_fd(fd);
    }

    fn file_type(&self) -> u8 {
        self.borrow().file_type()
    }

    fn session(&self) -> Option<Selector> {
        self.borrow().session()
    }

    fn remove(&mut self) {
        self.borrow().remove();
    }

    fn stat(&self) -> Result<super::FileInfo, Error> {
        self.borrow().stat()
    }

    fn path(&self) -> Result<String, Error> {
        self.borrow().path()
    }

    fn truncate(&mut self, length: usize) -> Result<(), Error> {
        self.borrow().truncate(length)
    }

    fn get_tmode(&self) -> Result<TMode, Error> {
        self.borrow().get_tmode()
    }

    fn delegate(&self, act: &ChildActivity) -> Result<Selector, Error> {
        self.borrow().delegate(act)
    }

    fn serialize(&self, s: &mut M3Serializer<VecSink<'_>>) {
        self.borrow().serialize(s);
    }

    fn is_blocking(&self) -> bool {
        self.borrow().is_blocking()
    }

    fn set_blocking(&mut self, blocking: bool) -> Result<(), Error> {
        self.borrow().set_blocking(blocking)
    }

    fn fetch_signal(&mut self) -> Result<bool, Error> {
        self.borrow().fetch_signal()
    }

    fn check_events(&mut self, events: FileEvent) -> bool {
        self.borrow().check_events(events)
    }
}

impl<T: ?Sized> Read for FileRef<T> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.borrow().read(buf)
    }
}

impl<T: ?Sized> Write for FileRef<T> {
    fn flush(&mut self) -> Result<(), Error> {
        self.borrow().flush()
    }

    fn sync(&mut self) -> Result<(), Error> {
        self.borrow().sync()
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.borrow().write(buf)
    }
}

impl<T: ?Sized> Seek for FileRef<T> {
    fn seek(&mut self, off: usize, whence: SeekMode) -> Result<usize, Error> {
        self.borrow().seek(off, whence)
    }
}

impl<T: ?Sized> Map for FileRef<T> {
    fn map(
        &self,
        pager: &Pager,
        virt: goff,
        off: usize,
        len: usize,
        prot: kif::Perm,
        flags: MapFlags,
    ) -> Result<(), Error> {
        self.borrow().map(pager, virt, off, len, prot, flags)
    }
}

impl<T: ?Sized> Hashed for FileRef<T> {
    fn hash(&self) -> Result<String, Error> {
        self.borrow().hash()
    }
}

impl<T: ?Sized> HashInput for FileRef<T> {
    fn hash_input(&mut self, sess: &HashSession, len: usize) -> Result<usize, Error> {
        self.borrow().hash_input(sess, len)
    }
}

impl<T: ?Sized> HashOutput for FileRef<T> {
    fn hash_output(&mut self, sess: &HashSession, len: usize) -> Result<usize, Error> {
        self.borrow().hash_output(sess, len)
    }
}

impl<T: 'static + Socket> Socket for FileRef<T> {
    fn state(&self) -> crate::net::State {
        self.borrow_as().state()
    }

    fn local_endpoint(&self) -> Option<crate::net::Endpoint> {
        self.borrow_as().local_endpoint()
    }

    fn remote_endpoint(&self) -> Option<crate::net::Endpoint> {
        self.borrow_as().remote_endpoint()
    }

    fn connect(&mut self, ep: crate::net::Endpoint) -> Result<(), Error> {
        self.borrow_as().connect(ep)
    }

    fn has_data(&self) -> bool {
        self.borrow_as().has_data()
    }

    fn recv(&mut self, data: &mut [u8]) -> Result<usize, Error> {
        self.borrow_as().recv(data)
    }

    fn send(&mut self, data: &[u8]) -> Result<usize, Error> {
        self.borrow_as().send(data)
    }
}

impl<T: 'static + DGramSocket> DGramSocket for FileRef<T> {
    fn bind(&mut self, port: crate::net::Port) -> Result<(), Error> {
        self.borrow_as().bind(port)
    }

    fn recv_from(&mut self, data: &mut [u8]) -> Result<(usize, crate::net::Endpoint), Error> {
        self.borrow_as().recv_from(data)
    }

    fn send_to(&mut self, data: &[u8], endpoint: crate::net::Endpoint) -> Result<(), Error> {
        self.borrow_as().send_to(data, endpoint)
    }
}

impl<T: 'static + StreamSocket> StreamSocket for FileRef<T> {
    fn listen(&mut self, port: crate::net::Port) -> Result<(), Error> {
        self.borrow_as().listen(port)
    }

    fn accept(&mut self) -> Result<crate::net::Endpoint, Error> {
        self.borrow_as().accept()
    }

    fn close(&mut self) -> Result<(), Error> {
        self.borrow_as().close()
    }

    fn abort(&mut self) -> Result<(), Error> {
        self.borrow_as().abort()
    }
}

impl<T: ?Sized> fmt::Debug for FileRef<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileRef[fd={}, file={:?}]", self.fd, self.borrow())
    }
}
