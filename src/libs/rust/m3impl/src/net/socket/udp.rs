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
use crate::errors::{Code, Error};
use crate::io;
use crate::net::{
    log_net,
    socket::{BaseSocket, DGramSocket, Socket, SocketArgs, State},
    Endpoint, NetLogEvent, Port, SocketType,
};
use crate::rc::Rc;
use crate::session::{HashInput, HashOutput, NetworkManager};
use crate::tiles::Activity;
use crate::vfs::{self, Fd, File, FileEvent, FileRef, INV_FD};

/// Configures the buffer sizes for datagram sockets
pub struct DgramSocketArgs {
    pub(crate) nm: Rc<NetworkManager>,
    pub(crate) args: SocketArgs,
}

impl DgramSocketArgs {
    /// Creates a new [`DgramSocketArgs`] with default settings.
    pub fn new(nm: Rc<NetworkManager>) -> Self {
        Self {
            nm,
            args: SocketArgs::default(),
        }
    }

    /// Sets the number of slots and the size in bytes of the receive buffer
    pub fn recv_buffer(mut self, slots: usize, size: usize) -> Self {
        self.args.rbuf_slots = slots;
        self.args.rbuf_size = size;
        self
    }

    /// Sets the number of slots and the size in bytes of the send buffer
    pub fn send_buffer(mut self, slots: usize, size: usize) -> Self {
        self.args.sbuf_slots = slots;
        self.args.sbuf_size = size;
        self
    }
}

/// Represents a datagram socket using the user datagram protocol (UDP)
pub struct UdpSocket {
    fd: Fd,
    socket: BaseSocket,
    nm: Rc<NetworkManager>,
}

impl UdpSocket {
    /// Creates a new UDP sockets with given arguments.
    ///
    /// By default, the socket is in blocking mode, that is, all functions
    /// ([`send_to`](UdpSocket::send_to), [`recv_from`](UdpSocket::recv_from), ...) do not return
    /// until the operation is complete. This can be changed via
    /// [`set_blocking`](UdpSocket::set_blocking).
    pub fn new(args: DgramSocketArgs) -> Result<FileRef<Self>, Error> {
        let sock = Box::new(UdpSocket {
            socket: args.nm.create(SocketType::Dgram, None, &args.args)?,
            nm: args.nm,
            fd: INV_FD,
        });
        let fd = Activity::own().files().add(sock)?;
        Ok(FileRef::new_owned(fd))
    }
}

impl Socket for UdpSocket {
    fn state(&self) -> State {
        self.socket.state()
    }

    fn local_endpoint(&self) -> Option<Endpoint> {
        self.socket.local_ep
    }

    fn remote_endpoint(&self) -> Option<Endpoint> {
        self.socket.remote_ep
    }

    fn connect(&mut self, ep: Endpoint) -> Result<(), Error> {
        if ep == Endpoint::unspecified() {
            return Err(Error::new(Code::InvArgs));
        }

        if self.socket.state() != State::Bound {
            self.bind(0)?;
        }

        self.socket.remote_ep = Some(ep);
        Ok(())
    }

    fn has_data(&self) -> bool {
        self.socket.has_data()
    }

    fn recv(&mut self, data: &mut [u8]) -> Result<usize, Error> {
        self.recv_from(data).map(|(size, _)| size)
    }

    fn send(&mut self, data: &[u8]) -> Result<usize, Error> {
        self.send_to(
            data,
            self.socket
                .remote_ep
                .ok_or_else(|| Error::new(Code::InvState))?,
        )
        .map(|_| data.len())
    }
}

impl DGramSocket for UdpSocket {
    fn bind(&mut self, port: Port) -> Result<(), Error> {
        if self.socket.state() != State::Closed {
            return Err(Error::new(Code::InvState));
        }

        let (addr, port) = self.nm.bind(self.socket.sd(), port)?;
        self.socket.local_ep = Some(Endpoint::new(addr, port));
        self.socket.state = State::Bound;
        Ok(())
    }

    fn recv_from(&mut self, data: &mut [u8]) -> Result<(usize, Endpoint), Error> {
        self.socket.next_data(data.len(), |buf, ep| {
            data[0..buf.len()].copy_from_slice(buf);
            (buf.len(), (buf.len(), ep))
        })
    }

    fn send_to(&mut self, data: &[u8], endpoint: Endpoint) -> Result<(), Error> {
        if self.socket.state() != State::Bound {
            self.bind(0)?;
        }

        log_net(NetLogEvent::SubmitData, self.socket.sd(), data.len());
        self.socket.send(data, endpoint)
    }
}

impl File for UdpSocket {
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
    /// In blocking mode, all functions ([`send_to`](UdpSocket::send_to),
    /// [`recv_from`](UdpSocket::recv_from), ...) do not return until the operation is complete. In
    /// non-blocking mode, all functions return in case they would need to block, that is, wait
    /// until an event is received or further data can be sent.
    fn set_blocking(&mut self, blocking: bool) -> Result<(), Error> {
        self.socket.set_blocking(blocking);
        Ok(())
    }

    fn check_events(&mut self, events: FileEvent) -> bool {
        self.socket.has_events(events)
    }
}

impl io::Read for UdpSocket {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.recv(buf)
    }
}

impl io::Write for UdpSocket {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.send(buf).map(|_| buf.len())
    }
}

impl vfs::Seek for UdpSocket {
}

impl vfs::Map for UdpSocket {
}

impl vfs::Hashed for UdpSocket {
}

impl HashInput for UdpSocket {
}

impl HashOutput for UdpSocket {
}

impl fmt::Debug for UdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UdpSocket")
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        self.socket.tear_down();
        self.nm.abort(self.socket.sd(), true).ok();
    }
}
