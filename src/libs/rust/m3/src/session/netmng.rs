/*
 * Copyright (C) 2021-2022 Nils Asmussen, Barkhausen Institut
 * Copyright (C) 2021, Tendsin Mende <tendsin.mende@mailbox.tu-dresden.de>
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

use base::int_enum;

use crate::com::{RecvGate, SendGate};
use crate::errors::Error;
use crate::net::{Endpoint, IpAddr, NetEventChannel, Port, Sd, Socket, SocketArgs, SocketType};
use crate::rc::Rc;
use crate::session::ClientSession;
use crate::vfs::GenFileOp;

int_enum! {
    /// The operations for the network service
    pub struct NetworkOp : u64 {
        const STAT          = GenFileOp::STAT.val;
        const SEEK          = GenFileOp::SEEK.val;
        #[allow(non_camel_case_types)]
        const NEXT_IN       = GenFileOp::NEXT_IN.val;
        #[allow(non_camel_case_types)]
        const NEXT_OUT      = GenFileOp::NEXT_OUT.val;
        const COMMIT        = GenFileOp::COMMIT.val;
        const TRUNCATE      = GenFileOp::TRUNCATE.val;
        // TODO what about GenericFile::CLOSE?
        const BIND          = 14;
        const LISTEN        = 15;
        const CONNECT       = 16;
        const ABORT         = 17;
        const CREATE        = 18;
        const GET_IP        = 19;
        const GET_NAMESRV   = 20;
        const GET_SGATE     = 21;
        const OPEN_FILE     = 22;
    }
}

/// Represents a session at the network service, allowing to create and use sockets
///
/// To exchange events and data with the server, the [`NetEventChannel`] is used, which allows to
/// send and receive multiple messages. Events are used to receive connected or closed events from
/// the server and to send close requests to the server. Transmitted and received data is exchanged
/// via the [`NetEventChannel`] in both directions.
pub struct NetworkManager {
    #[allow(dead_code)] // Needs to keep the session alive
    client_session: ClientSession,
    metagate: SendGate,
}

impl NetworkManager {
    /// Creates a new instance for `service`
    pub fn new(service: &str) -> Result<Rc<Self>, Error> {
        let client_session = ClientSession::new(service)?;

        // Obtain meta gate for the service
        let sgate_crd = client_session.obtain(
            1,
            |sink| sink.push_word(NetworkOp::GET_SGATE.val),
            |_source| Ok(()),
        )?;

        Ok(Rc::new(NetworkManager {
            client_session,
            metagate: SendGate::new_bind(sgate_crd.start()),
        }))
    }

    /// Returns the local IP address
    pub fn ip_addr(&self) -> Result<IpAddr, Error> {
        let mut reply = send_recv_res!(&self.metagate, RecvGate::def(), NetworkOp::GET_IP)?;
        let addr = IpAddr(reply.pop::<u32>()?);
        Ok(addr)
    }

    pub(crate) fn create(
        &self,
        ty: SocketType,
        protocol: Option<u8>,
        args: &SocketArgs,
    ) -> Result<Socket, Error> {
        let mut sd = 0;
        let crd = self.client_session.obtain(
            2,
            |sink| {
                sink.push_word(NetworkOp::CREATE.val);
                sink.push_word(ty as u64);
                sink.push_word(protocol.unwrap_or(0) as u64);
                sink.push_word(args.rbuf_size as u64);
                sink.push_word(args.rbuf_slots as u64);
                sink.push_word(args.sbuf_size as u64);
                sink.push_word(args.sbuf_slots as u64);
            },
            |source| {
                sd = source.pop_word()? as Sd;
                Ok(())
            },
        )?;

        let chan = NetEventChannel::new_client(crd.start())?;
        Ok(Socket::new(sd, ty, chan))
    }

    pub(crate) fn nameserver(&self) -> Result<IpAddr, Error> {
        let mut reply = send_recv_res!(&self.metagate, RecvGate::def(), NetworkOp::GET_NAMESRV)?;
        let addr = IpAddr(reply.pop::<u32>()?);
        Ok(addr)
    }

    pub(crate) fn bind(&self, sd: Sd, port: Port) -> Result<(IpAddr, Port), Error> {
        let mut reply = send_recv_res!(&self.metagate, RecvGate::def(), NetworkOp::BIND, sd, port)?;
        let addr = IpAddr(reply.pop::<u32>()?);
        let port = reply.pop::<Port>()?;
        Ok((addr, port))
    }

    pub(crate) fn listen(&self, sd: Sd, port: Port) -> Result<IpAddr, Error> {
        let mut reply =
            send_recv_res!(&self.metagate, RecvGate::def(), NetworkOp::LISTEN, sd, port)?;
        let addr = IpAddr(reply.pop::<u32>()?);
        Ok(addr)
    }

    pub(crate) fn connect(&self, sd: Sd, endpoint: Endpoint) -> Result<Endpoint, Error> {
        let mut reply = send_recv_res!(
            &self.metagate,
            RecvGate::def(),
            NetworkOp::CONNECT,
            sd,
            endpoint.addr.0,
            endpoint.port
        )?;
        let addr = reply.pop::<u32>()?;
        let port = reply.pop::<Port>()?;
        Ok(Endpoint::new(IpAddr(addr), port))
    }

    pub(crate) fn abort(&self, sd: Sd, remove: bool) -> Result<(), Error> {
        send_recv_res!(
            &self.metagate,
            RecvGate::def(),
            NetworkOp::ABORT,
            sd,
            remove
        )
        .map(|_| ())
    }
}
