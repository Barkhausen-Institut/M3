/*
 * Copyright (C) 2021-2022 Nils Asmussen, Barkhausen Institut
 * Copyright (C) 2021, Tendsin Mende <tendsin.mende@mailbox.tu-dresden.de>
 * Copyright (C) 2017, Georg Kotheimer <georg.kotheimer@mailbox.tu-dresden.de>
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
use crate::errors::Error;
use crate::io;
use crate::net::{
    log_net,
    socket::{BaseSocket, DgramSocketArgs},
    Endpoint, NetLogEvent, SocketType,
};
use crate::rc::Rc;
use crate::session::{HashInput, HashOutput, NetworkManager};
use crate::tiles::Activity;
use crate::vfs::{self, Fd, File, FileEvent, FileRef, INV_FD};

pub type RawSocketArgs = DgramSocketArgs;

/// Represents a raw internet protocol (IP) socket
pub struct RawSocket {
    fd: Fd,
    socket: BaseSocket,
    nm: Rc<NetworkManager>,
}

impl RawSocket {
    /// Creates a new raw IP socket with given arguments.
    ///
    /// By default, the socket is in blocking mode, that is, all functions
    /// ([`send`](RawSocket::send), [`recv`](RawSocket::recv), ...) do not return until the
    /// operation is complete. This can be changed via [`set_blocking`](RawSocket::set_blocking).
    ///
    /// Creation of a raw socket requires that the used session has permission to do so. This is
    /// controlled with the "raw=yes" argument in the session argument of M³'s config files.
    pub fn new(args: RawSocketArgs, protocol: Option<u8>) -> Result<FileRef<Self>, Error> {
        let sock = Box::new(RawSocket {
            socket: args.nm.create(SocketType::Raw, protocol, &args.args)?,
            nm: args.nm,
            fd: INV_FD,
        });
        let fd = Activity::own().files().add(sock)?;
        Ok(FileRef::new_owned(fd))
    }

    /// Returns whether data can currently be received from the socket
    ///
    /// Note that this function does not process events. To receive data, any receive function on
    /// this socket or [`FileWaiter::wait`](crate::vfs::FileWaiter::wait) has to be called.
    pub fn has_data(&self) -> bool {
        self.socket.has_data()
    }

    /// Receives data from the socket into the given buffer.
    ///
    /// Returns the number of received bytes.
    pub fn recv(&mut self, data: &mut [u8]) -> Result<usize, Error> {
        self.socket.next_data(data.len(), |buf, _ep| {
            data[0..buf.len()].copy_from_slice(buf);
            (buf.len(), buf.len())
        })
    }

    /// Sends the given data to the given remote endpoint
    pub fn send(&self, data: &[u8]) -> Result<(), Error> {
        log_net(NetLogEvent::SubmitData, self.socket.sd(), data.len());
        self.socket.send(data, Endpoint::unspecified())
    }
}

impl File for RawSocket {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn fd(&self) -> Fd {
        self.fd
    }

    fn set_fd(&mut self, fd: Fd) {
        self.fd = fd;
    }

    fn file_type(&self) -> u8 {
        // not supported
        b'\0'
    }

    fn is_blocking(&self) -> bool {
        self.socket.blocking()
    }

    /// Sets whether the socket is using blocking mode.
    ///
    /// In blocking mode, all functions ([`send`](RawSocket::send), [`recv`](RawSocket::recv), ...)
    /// do not return until the operation is complete. In non-blocking mode, all functions return in
    /// case they would need to block, that is, wait until an event is received or further data can
    /// be sent.
    fn set_blocking(&mut self, blocking: bool) -> Result<(), Error> {
        self.socket.set_blocking(blocking);
        Ok(())
    }

    fn check_events(&mut self, events: FileEvent) -> bool {
        self.socket.has_events(events)
    }
}

impl io::Read for RawSocket {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.recv(buf)
    }
}

impl io::Write for RawSocket {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.send(buf).map(|_| buf.len())
    }
}

impl vfs::Seek for RawSocket {
}

impl vfs::Map for RawSocket {
}

impl vfs::Hashed for RawSocket {
}

impl HashInput for RawSocket {
}

impl HashOutput for RawSocket {
}

impl fmt::Debug for RawSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RawSocket")
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        self.socket.tear_down();
        self.nm.abort(self.socket.sd(), true).ok();
    }
}
