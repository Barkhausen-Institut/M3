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

use core::cmp;

use m3::cap::Selector;
use m3::cell::RefCell;
use m3::col::Vec;
use m3::com::{GateIStream, RecvGate, SendGate};
use m3::errors::{Code, Error};
use m3::kif::{CapRngDesc, CapType};
use m3::net::{IpAddr, Port, Sd, SocketArgs, SocketType, MTU};
use m3::parse;
use m3::rc::Rc;
use m3::serialize::Source;
use m3::server::CapExchange;
use m3::session::{NetworkOp, ServerSession};
use m3::tcu;
use m3::vfs::OpenFlags;
use m3::{log, reply_vmsg, vec};

use crate::driver::DriverInterface;
use crate::ports::{self, AnyPort};
use crate::sess::file::FileSession;
use crate::smoltcpif::socket::{to_m3_addr, to_m3_ep, SendNetEvent, Socket};

struct Settings {
    bufs: usize,
    socks: usize,
    raw: bool,
    tcp_ports: Vec<(Port, Port)>,
    udp_ports: Vec<(Port, Port)>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            bufs: 64 * 1024,
            socks: 4,
            raw: false,
            tcp_ports: Vec::new(),
            udp_ports: Vec::new(),
        }
    }
}

fn parse_ports(port_descs: &str, ports: &mut Vec<(Port, Port)>) -> Result<(), Error> {
    // comma separated list of "x-y" or "x"
    for port_desc in port_descs.split(',') {
        let range = if let Some(pos) = port_desc.find('-') {
            let from = parse::int(&port_desc[0..pos])? as Port;
            let to = parse::int(&port_desc[(pos + 1)..])? as Port;
            (from, to)
        }
        else {
            let port = parse::int(port_desc)? as Port;
            (port, port)
        };

        if ports::is_ephemeral(range.0) || ports::is_ephemeral(range.1) {
            log!(crate::LOG_ERR, "Cannot bind/listen on ephemeral ports");
            return Err(Error::new(Code::InvArgs));
        }

        ports.push(range);
    }
    Ok(())
}

fn parse_arguments(args_str: &str) -> Result<Settings, Error> {
    let mut args = Settings::default();
    for arg in args_str.split_whitespace() {
        if let Some(bufs) = arg.strip_prefix("bufs=") {
            args.bufs = parse::size(bufs)?;
        }
        else if let Some(socks) = arg.strip_prefix("socks=") {
            args.socks = parse::int(socks)? as usize;
        }
        else if arg == "raw=yes" {
            args.raw = true;
        }
        else if let Some(portdesc) = arg.strip_prefix("tcp=") {
            parse_ports(portdesc, &mut args.tcp_ports)?;
        }
        else if let Some(portdesc) = arg.strip_prefix("udp=") {
            parse_ports(portdesc, &mut args.udp_ports)?;
        }
        else {
            return Err(Error::new(Code::InvArgs));
        }
    }
    Ok(args)
}

pub struct SocketSession {
    // client send gate to send us requests
    sgate: Option<SendGate>,
    // our receive gate (shared among all sessions)
    rgate: Rc<RecvGate>,
    // the settings for this session
    settings: Settings,
    // our session cap
    server_session: ServerSession,
    // sockets the client has open
    sockets: Vec<Option<Rc<RefCell<Socket>>>>,
}

impl SocketSession {
    pub fn new(
        _crt: usize,
        args_str: &str,
        server_session: ServerSession,
        rgate: Rc<RecvGate>,
    ) -> Result<Self, Error> {
        let settings = parse_arguments(args_str).map_err(|e| {
            log!(
                crate::LOG_ERR,
                "Unable to parse session arguments: '{}'",
                args_str
            );
            e
        })?;

        Ok(SocketSession {
            sgate: None,
            rgate,
            server_session,
            sockets: vec![None; settings.socks],
            settings,
        })
    }

    pub fn obtain(
        &mut self,
        crt: usize,
        srv_sel: Selector,
        xchg: &mut CapExchange<'_>,
        iface: &mut DriverInterface<'_>,
    ) -> Result<(), Error> {
        let is = xchg.in_args();
        let op = is.pop::<NetworkOp>()?;

        match op {
            NetworkOp::GET_SGATE => {
                let caps = self.get_sgate()?;
                xchg.out_caps(caps);
                Ok(())
            },
            NetworkOp::CREATE => {
                let (caps, sd) = self.create_socket(is, iface)?;
                xchg.out_caps(caps);
                xchg.out_args().push_word(sd as u64);
                Ok(())
            },
            NetworkOp::OPEN_FILE => {
                let caps = self.open_file(crt, srv_sel, is)?;
                xchg.out_caps(caps);
                Ok(())
            },
            _ => Err(Error::new(Code::InvArgs)),
        }
    }

    fn get_sgate(&mut self) -> Result<CapRngDesc, Error> {
        if self.sgate.is_some() {
            return Err(Error::new(Code::InvArgs));
        }

        let label = self.server_session.ident() as tcu::Label;
        self.sgate = Some(SendGate::new_with(
            m3::com::SGateArgs::new(&self.rgate).label(label).credits(1),
        )?);

        Ok(CapRngDesc::new(
            CapType::OBJECT,
            self.sgate.as_ref().unwrap().sel(),
            1,
        ))
    }

    fn open_file(
        &mut self,
        crt: usize,
        srv_sel: Selector,
        is: &mut Source<'_>,
    ) -> Result<CapRngDesc, Error> {
        let sd = is.pop::<Sd>().expect("Failed to get sd");
        let mode = is.pop::<u32>().expect("Failed to get mode");
        let rmemsize = is.pop::<usize>().expect("Failed to get rmemsize");
        let smemsize = is.pop::<usize>().expect("Failed to get smemsize");

        log!(
            crate::LOG_SESS,
            "socket_session::open_file(sd={}, mode={}, rmemsize={}, smemsize={})",
            sd,
            mode,
            rmemsize,
            smemsize
        );
        // Create socket for file
        let socket = self.get_socket(sd)?;
        if (mode & OpenFlags::RW.bits()) == 0 {
            log!(crate::LOG_SESS, "open_file failed: invalid mode");
            return Err(Error::new(Code::InvArgs));
        }

        if (socket.borrow().recv_file().is_some() && ((mode & OpenFlags::R.bits()) > 0))
            || (socket.borrow().send_file().is_some() && ((mode & OpenFlags::W.bits()) > 0))
        {
            log!(
                crate::LOG_SESS,
                "open_file failed: socket already has a file session attached"
            );
            return Err(Error::new(Code::InvArgs));
        }
        let file = FileSession::new(
            crt,
            srv_sel,
            socket.clone(),
            &self.rgate,
            mode,
            rmemsize,
            smemsize,
        )?;
        if file.borrow().is_recv() {
            socket.borrow_mut().set_recv_file(Some(file.clone()));
        }
        if file.borrow().is_send() {
            socket.borrow_mut().set_send_file(Some(file.clone()));
        }

        log!(
            crate::LOG_SESS,
            "open_file: {}@{}{}",
            sd,
            if file.borrow().is_recv() { "r" } else { "" },
            if file.borrow().is_send() { "s" } else { "" }
        );

        let caps = file.borrow().caps();
        Ok(caps)
    }

    fn get_socket(&self, sd: Sd) -> Result<Rc<RefCell<Socket>>, Error> {
        match self.sockets.get(sd) {
            Some(Some(s)) => Ok(s.clone()),
            _ => Err(Error::new(Code::InvArgs)),
        }
    }

    fn add_socket(
        &mut self,
        ty: SocketType,
        protocol: u8,
        args: &SocketArgs,
        caps: Selector,
        iface: &mut DriverInterface<'_>,
    ) -> Result<Sd, Error> {
        if ty == SocketType::Raw && !self.settings.raw {
            return Err(Error::new(Code::NoPerm));
        }

        let total_space = Socket::required_space(ty, args);
        if self.settings.bufs < total_space {
            return Err(Error::new(Code::NoSpace));
        }

        for (i, s) in self.sockets.iter_mut().enumerate() {
            if s.is_none() {
                *s = Some(Rc::new(RefCell::new(Socket::new(
                    i, ty, protocol, args, caps, iface,
                )?)));
                self.settings.bufs -= total_space;
                return Ok(i);
            }
        }
        Err(Error::new(Code::NoSpace))
    }

    fn remove_socket(&mut self, sd: Sd) {
        if let Some(s) = self.sockets[sd].take() {
            self.settings.bufs += s.borrow().buffer_space();
        }
    }

    fn create_socket(
        &mut self,
        is: &mut Source<'_>,
        iface: &mut DriverInterface<'_>,
    ) -> Result<(CapRngDesc, Sd), Error> {
        let ty = SocketType::from_usize(is.pop::<usize>()?);
        let protocol: u8 = is.pop()?;
        let rbuf_size: usize = is.pop()?;
        let rbuf_slots: usize = is.pop()?;
        let sbuf_size: usize = is.pop()?;
        let sbuf_slots: usize = is.pop()?;

        // 2 caps for us, 2 for the client
        let caps = m3::tiles::Activity::own().alloc_sels(4);

        let res = self.add_socket(
            ty,
            protocol,
            &SocketArgs {
                rbuf_slots,
                rbuf_size,
                sbuf_slots,
                sbuf_size,
            },
            caps,
            iface,
        );

        log!(
            crate::LOG_SESS,
            "net::create(type={:?}, protocol={}, rbuf=[{}b,{}], sbuf=[{}b,{}]) -> {:?}",
            ty,
            protocol,
            rbuf_size,
            rbuf_slots,
            sbuf_size,
            sbuf_slots,
            res
        );

        match res {
            Ok(sd) => {
                // Send capabilities back to caller so it can connect to the created gates
                let caps = CapRngDesc::new(CapType::OBJECT, caps + 2, 2);
                Ok((caps, sd))
            },

            Err(e) => Err(e),
        }
    }

    fn can_use_port(&self, ty: SocketType, port: Port) -> bool {
        let ports = match ty {
            SocketType::Stream => &self.settings.tcp_ports,
            SocketType::Dgram => &self.settings.udp_ports,
            _ => return true,
        };
        for range in ports {
            if port >= range.0 && port <= range.1 {
                return true;
            }
        }
        false
    }

    pub fn bind(
        &mut self,
        is: &mut GateIStream<'_>,
        iface: &mut DriverInterface<'_>,
    ) -> Result<(), Error> {
        let sd: Sd = is.pop()?;
        let port: Port = is.pop()?;

        log!(
            crate::LOG_SESS,
            "[{}] net::bind(sd={}, port={})",
            self.server_session.ident(),
            sd,
            port
        );

        let sock = self.get_socket(sd)?;
        let port = if port == 0 {
            AnyPort::Ephemeral(ports::alloc())
        }
        else {
            if !self.can_use_port(sock.borrow().socket_type(), port) {
                return Err(Error::new(Code::NoPerm));
            }

            AnyPort::Manual(port)
        };

        let port_no = port.number();
        sock.borrow_mut().bind(crate::own_ip(), port, iface)?;

        let addr = to_m3_addr(crate::own_ip());
        reply_vmsg!(is, Code::None as i32, addr.0, port_no)
    }

    pub fn listen(
        &mut self,
        is: &mut GateIStream<'_>,
        iface: &mut DriverInterface<'_>,
    ) -> Result<(), Error> {
        let sd: Sd = is.pop()?;
        let port: Port = is.pop()?;

        log!(
            crate::LOG_SESS,
            "[{}] net::listen(sd={}, port={})",
            self.server_session.ident(),
            sd,
            port
        );

        let sock = self.get_socket(sd)?;
        if !self.can_use_port(sock.borrow().socket_type(), port) {
            return Err(Error::new(Code::NoPerm));
        }

        sock.borrow_mut().listen(iface, crate::own_ip(), port)?;

        let addr = to_m3_addr(crate::own_ip());
        reply_vmsg!(is, Code::None as i32, addr.0)
    }

    pub fn connect(
        &mut self,
        is: &mut GateIStream<'_>,
        iface: &mut DriverInterface<'_>,
    ) -> Result<(), Error> {
        let sd: Sd = is.pop()?;
        let remote_addr = IpAddr(is.pop::<u32>()?);
        let remote_port: Port = is.pop()?;

        let local_port = ports::alloc();
        log!(
            crate::LOG_SESS,
            "[{}] net::connect(sd={}, remote={}:{}, local={})",
            self.server_session.ident(),
            sd,
            remote_addr,
            remote_port,
            local_port
        );

        let sock = self.get_socket(sd)?;
        let port_no = *local_port;
        sock.borrow_mut()
            .connect(remote_addr, remote_port, local_port, iface)?;

        let addr = to_m3_addr(crate::own_ip());
        reply_vmsg!(is, Code::None as i32, addr.0, port_no)
    }

    pub fn abort(
        &mut self,
        is: &mut GateIStream<'_>,
        iface: &mut DriverInterface<'_>,
    ) -> Result<(), Error> {
        let sd: Sd = is.pop()?;
        let remove: bool = is.pop()?;

        self.do_abort(sd, remove, iface)?;
        is.reply_error(Code::None)
    }

    pub fn close(&mut self, iface: &mut DriverInterface<'_>) -> Result<(), Error> {
        for sd in 0..self.sockets.len() {
            self.do_abort(sd, true, iface).ok();
        }
        Ok(())
    }

    fn do_abort(
        &mut self,
        sd: Sd,
        remove: bool,
        iface: &mut DriverInterface<'_>,
    ) -> Result<(), Error> {
        log!(
            crate::LOG_SESS,
            "[{}] net::abort(sd={}, remove={})",
            self.server_session.ident(),
            sd,
            remove
        );

        let socket = self.get_socket(sd)?;
        socket.borrow_mut().abort(iface);
        if remove {
            self.remove_socket(sd);
        }
        Ok(())
    }

    pub fn process_incoming(&mut self, iface: &mut DriverInterface<'_>) -> bool {
        let sess = self.server_session.ident();
        let mut needs_recheck = false;

        // iterate over all sockets and check for events
        'outer_loop: for idx in 0..self.sockets.len() {
            if let Some(socket) = self.sockets.get(idx).unwrap() {
                let mut sock = socket.borrow_mut();
                let chan = sock.channel().clone();

                chan.fetch_replies();

                if sock.process_queued_events(sess, iface) {
                    needs_recheck = true;
                    continue 'outer_loop;
                }

                // receive everything in the channel
                while let Some(event) = chan.receive_event() {
                    if sock.process_event(sess, iface, event) {
                        needs_recheck = true;
                        continue 'outer_loop;
                    }
                }
            }
        }

        needs_recheck
    }

    pub fn process_outgoing(&mut self, iface: &mut DriverInterface<'_>) -> bool {
        let mut needs_recheck = false;
        // iterate over all sockets and try to receive
        for socket in self.sockets.iter().flatten() {
            let socket_sd = socket.borrow().sd();
            let chan = socket.borrow().channel().clone();

            loop {
                chan.fetch_replies();

                // if we don't have credits anymore to send events, stop here. we'll get a reply
                // to one of our earlier events and get credits back with this, so that we'll wake
                // up from a potential sleep and call receive again.
                if !chan.can_send().unwrap() {
                    needs_recheck = true;
                    break;
                }

                if let Some(event) = socket.borrow_mut().fetch_event(iface) {
                    log!(
                        crate::LOG_DATA,
                        "[{}] socket {}: received event {:?}",
                        socket_sd,
                        self.server_session.ident(),
                        event,
                    );

                    // the match is needed, because we don't want to send the enum, but the
                    // contained event struct
                    match event {
                        SendNetEvent::Connected(e) => chan.send_event(e).unwrap(),
                        SendNetEvent::Closed(e) => chan.send_event(e).unwrap(),
                        SendNetEvent::CloseReq(e) => chan.send_event(e).unwrap(),
                    }
                }

                if !chan.can_send().unwrap() {
                    needs_recheck = true;
                    break;
                }

                let mut received = false;
                socket.borrow_mut().receive(iface, |data, addr| {
                    let ep = to_m3_ep(addr);
                    let amount = cmp::min(MTU, data.len());

                    log!(
                        crate::LOG_DATA,
                        "[{}] socket {}: received packet with {}b from {}",
                        socket_sd,
                        self.server_session.ident(),
                        amount,
                        ep
                    );

                    if let Err(e) = chan.send_data(ep, amount, |buf| {
                        buf[0..amount].copy_from_slice(&data[0..amount]);
                    }) {
                        log!(
                            crate::LOG_ERR,
                            "[{}] socket {}: sending received packet with {}b failed: {}",
                            socket_sd,
                            self.server_session.ident(),
                            amount,
                            e
                        );
                    }
                    received = true;
                    amount
                });

                if !received {
                    break;
                }
            }
        }
        needs_recheck
    }
}
