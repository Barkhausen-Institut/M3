/*
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

#![no_std]

mod chan;
mod meta;
mod pipe;
mod sess;

use m3::cap::Selector;
use m3::cell::LazyReadOnlyCell;
use m3::col::{String, Vec};
use m3::com::{GateIStream, RecvGate};
use m3::env;
use m3::errors::{Code, Error};
use m3::int_enum;
use m3::kif;
use m3::log;
use m3::println;
use m3::server::{
    server_loop, CapExchange, Handler, RequestHandler, Server, SessId, SessionContainer,
    DEF_MAX_CLIENTS, DEF_MSG_SIZE,
};
use m3::session::{PipeOperation, ServerSession};
use m3::tcu::Label;
use m3::tiles::Activity;
use m3::vec;
use m3::vfs::GenFileOp;

use chan::{ChanType, Channel};
use meta::Meta;
use sess::{PipesSession, SessionData};

pub const LOG_DEF: bool = false;

static REQHDL: LazyReadOnlyCell<RequestHandler> = LazyReadOnlyCell::default();

int_enum! {
    pub struct Operation : u64 {
        const STAT          = GenFileOp::STAT.val;
        const SEEK          = GenFileOp::SEEK.val;
        const NEXT_IN       = GenFileOp::NEXT_IN.val;
        const NEXT_OUT      = GenFileOp::NEXT_OUT.val;
        const COMMIT        = GenFileOp::COMMIT.val;
        const SYNC          = GenFileOp::SYNC.val;
        const CLOSE         = GenFileOp::CLOSE.val;
        const CLONE         = GenFileOp::CLONE.val;
        const GET_HASH      = GenFileOp::GET_HASH.val;
        const SET_TMODE     = GenFileOp::SET_TMODE.val;
        const SET_DEST      = GenFileOp::SET_DEST.val;
        const ENABLE_NOTIFY = GenFileOp::ENABLE_NOTIFY.val;
        const REQ_NOTIFY    = GenFileOp::REQ_NOTIFY.val;
        const OPEN_PIPE     = PipeOperation::OPEN_PIPE.val;
        const OPEN_CHAN     = PipeOperation::OPEN_CHAN.val;
        const SET_MEM       = PipeOperation::SET_MEM.val;
        const CLOSE_PIPE    = PipeOperation::CLOSE_PIPE.val;
    }
}

struct PipesHandler {
    sel: Selector,
    sessions: SessionContainer<PipesSession>,
}

impl PipesHandler {
    fn new_sub_sess(
        &self,
        crt: usize,
        sel: Selector,
        nsid: SessId,
        data: SessionData,
    ) -> Result<PipesSession, Error> {
        // let the kernel close the session as soon as the client dies or the session is revoked
        // for some other reason. this is required to signal EOF to the other side of the pipe.
        Ok(PipesSession::new(
            crt,
            ServerSession::new_with_sel(self.sel, sel, crt, nsid as u64, true)?,
            data,
        ))
    }

    fn close_sess(&mut self, sid: SessId, rgate: &RecvGate) -> Result<(), Error> {
        // close this and all child sessions
        let mut sids = vec![sid];
        while let Some(id) = sids.pop() {
            if let Some(sess) = self.sessions.get_mut(id) {
                log!(crate::LOG_DEF, "[{}] pipes::close(): closing {}", sid, id);

                // ignore errors here
                let _ = match &mut sess.data_mut() {
                    SessionData::Meta(ref mut m) => m.close(&mut sids),
                    SessionData::Pipe(ref mut p) => p.close(&mut sids),
                    SessionData::Chan(ref mut c) => c.close(&mut sids, rgate),
                };

                let crt = sess.creator();
                self.sessions.remove(crt, id);
                // ignore all potentially outstanding messages of this session
                rgate.drop_msgs_with(id as Label).unwrap();
            }
        }
        Ok(())
    }

    fn with_chan<F, R>(&mut self, is: &mut GateIStream<'_>, func: F) -> Result<R, Error>
    where
        F: Fn(&mut Channel, &mut GateIStream<'_>) -> Result<R, Error>,
    {
        let sess = self.sessions.get_mut(is.label() as SessId).unwrap();
        match &mut sess.data_mut() {
            SessionData::Chan(c) => func(c, is),
            _ => Err(Error::new(Code::InvArgs)),
        }
    }
}

impl Handler<PipesSession> for PipesHandler {
    fn sessions(&mut self) -> &mut m3::server::SessionContainer<PipesSession> {
        &mut self.sessions
    }

    fn open(
        &mut self,
        crt: usize,
        srv_sel: Selector,
        _arg: &str,
    ) -> Result<(Selector, SessId), Error> {
        self.sessions.add_next(crt, srv_sel, true, |sess| {
            log!(crate::LOG_DEF, "[{}] pipes::new_meta()", sess.ident());
            Ok(PipesSession::new(
                crt,
                sess,
                SessionData::Meta(Meta::default()),
            ))
        })
    }

    fn obtain(&mut self, crt: usize, sid: SessId, xchg: &mut CapExchange<'_>) -> Result<(), Error> {
        let op: Operation = xchg.in_args().pop().unwrap();
        log!(
            crate::LOG_DEF,
            "[{}] pipes::obtain(crt={}, op={})",
            sid,
            crt,
            op
        );

        if xchg.in_caps() != 2 {
            return Err(Error::new(Code::InvArgs));
        }
        if !self.sessions.can_add(crt) {
            return Err(Error::new(Code::NoSpace));
        }

        let res: Result<_, Error> = {
            let nsid = self.sessions.next_id()?;
            let osess = self.sessions.get_mut(sid).unwrap();
            match &mut osess.data_mut() {
                // meta sessions allow to create new pipes
                SessionData::Meta(ref mut m) => {
                    if op != Operation::OPEN_PIPE {
                        return Err(Error::new(Code::InvArgs));
                    }

                    let sel = Activity::own().alloc_sels(2);
                    let msize: usize = xchg.in_args().pop()?;
                    log!(
                        crate::LOG_DEF,
                        "[{}] pipes::open_pipe(sid={}, sel={}, size={:#x})",
                        sid,
                        nsid,
                        sel,
                        msize
                    );
                    let pipe = m.create_pipe(sel, nsid, msize, REQHDL.get().recv_gate())?;
                    let nsess = self.new_sub_sess(crt, sel, nsid, SessionData::Pipe(pipe))?;
                    Ok((nsid, nsess, false))
                },

                // pipe sessions allow to create new channels
                SessionData::Pipe(ref mut p) => {
                    if op != Operation::OPEN_CHAN {
                        return Err(Error::new(Code::InvArgs));
                    }

                    let sel = Activity::own().alloc_sels(2);
                    let ty = match xchg.in_args().pop()? {
                        1 => ChanType::READ,
                        _ => ChanType::WRITE,
                    };
                    log!(
                        crate::LOG_DEF,
                        "[{}] pipes::open_chan(sid={}, sel={}, ty={:?})",
                        sid,
                        nsid,
                        sel,
                        ty
                    );
                    let chan = p.new_chan(nsid, sel, ty, REQHDL.get().recv_gate())?;
                    p.attach(&chan);
                    let nsess = self.new_sub_sess(crt, sel, nsid, SessionData::Chan(chan))?;
                    Ok((nsid, nsess, false))
                },

                // channel sessions can be cloned
                SessionData::Chan(ref mut c) => {
                    if op != Operation::CLONE {
                        return Err(Error::new(Code::InvArgs));
                    }

                    let sel = Activity::own().alloc_sels(2);
                    log!(
                        crate::LOG_DEF,
                        "[{}] pipes::clone(sid={}, sel={})",
                        sid,
                        nsid,
                        sel
                    );

                    let chan = c.clone(nsid, sel, REQHDL.get().recv_gate())?;
                    let nsess = self.new_sub_sess(crt, sel, nsid, SessionData::Chan(chan))?;
                    Ok((nsid, nsess, true))
                },
            }
        };
        let (nsid, nsess, attach_pipe) = res?;

        let crd = if let SessionData::Chan(ref c) = nsess.data() {
            // workaround because we cannot borrow self.sessions again inside the above match
            if attach_pipe {
                let psess = self.sessions.get_mut(c.pipe()).unwrap();
                if let SessionData::Pipe(ref mut p) = psess.data_mut() {
                    p.attach(c);
                }
            }

            c.crd()
        }
        else if let SessionData::Pipe(_) = nsess.data() {
            kif::CapRngDesc::new(kif::CapType::OBJECT, nsess.sel(), 2)
        }
        else {
            kif::CapRngDesc::new(kif::CapType::OBJECT, nsess.sel(), 1)
        };

        // cannot fail because of the check above
        self.sessions.add(crt, nsid, nsess).unwrap();

        xchg.out_caps(crd);

        Ok(())
    }

    fn delegate(
        &mut self,
        _crt: usize,
        sid: SessId,
        xchg: &mut CapExchange<'_>,
    ) -> Result<(), Error> {
        let sess = self.sessions.get_mut(sid).unwrap();
        let op: Operation = xchg.in_args().pop()?;
        log!(crate::LOG_DEF, "[{}] pipes::delegate(op={})", sid, op);

        match &mut sess.data_mut() {
            // pipe sessions expect a memory cap for the shared memory of the pipe
            SessionData::Pipe(ref mut p) => match op {
                Operation::SET_MEM => {
                    if xchg.in_caps() != 1 || p.has_mem() {
                        return Err(Error::new(Code::InvArgs));
                    }

                    let sel = Activity::own().alloc_sel();
                    log!(crate::LOG_DEF, "[{}] pipes::set_mem(sel={})", sid, sel);
                    p.set_mem(sel);
                    xchg.out_caps(kif::CapRngDesc::new(kif::CapType::OBJECT, sel, 1));

                    Ok(())
                },
                _ => Err(Error::new(Code::InvArgs)),
            },

            // channel sessions expect an EP cap to get access to the data
            SessionData::Chan(ref mut c) => match op {
                Operation::SET_DEST => {
                    if xchg.in_caps() != 1 {
                        return Err(Error::new(Code::InvArgs));
                    }

                    let sel = Activity::own().alloc_sel();
                    log!(crate::LOG_DEF, "[{}] pipes::set_ep(sel={})", sid, sel);
                    c.set_ep(sel);
                    xchg.out_caps(kif::CapRngDesc::new(kif::CapType::OBJECT, sel, 1));

                    Ok(())
                },

                Operation::ENABLE_NOTIFY => {
                    if xchg.in_caps() != 1 {
                        return Err(Error::new(Code::InvArgs));
                    }

                    let sel = Activity::own().alloc_sel();
                    log!(
                        crate::LOG_DEF,
                        "[{}] pipes::enable_notify(sel={})",
                        sid,
                        sel
                    );
                    c.enable_notify(sel)?;
                    xchg.out_caps(kif::CapRngDesc::new(kif::CapType::OBJECT, sel, 1));
                    Ok(())
                },

                _ => Err(Error::new(Code::InvArgs)),
            },

            SessionData::Meta(_) => Err(Error::new(Code::InvArgs)),
        }
    }

    fn close(&mut self, _crt: usize, sid: SessId) {
        self.close_sess(sid, REQHDL.get().recv_gate()).ok();
    }
}

#[derive(Clone, Debug)]
pub struct PipesSettings {
    max_clients: usize,
}

impl Default for PipesSettings {
    fn default() -> Self {
        PipesSettings {
            max_clients: DEF_MAX_CLIENTS,
        }
    }
}

fn usage() -> ! {
    println!("Usage: {} [-m <clients>]", env::args().next().unwrap());
    println!();
    println!("  -m: the maximum number of clients (receive slots)");
    Activity::own().exit_with(Code::InvArgs);
}

fn parse_args() -> Result<PipesSettings, String> {
    let mut settings = PipesSettings::default();

    let args: Vec<&str> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i] {
            "-m" => {
                settings.max_clients = args[i + 1]
                    .parse::<usize>()
                    .map_err(|_| String::from("Failed to parse client count"))?;
                i += 1;
            },
            _ => break,
        }
        i += 1;
    }
    Ok(settings)
}

#[no_mangle]
pub fn main() -> Result<(), Error> {
    let settings = parse_args().unwrap_or_else(|e| {
        println!("Invalid arguments: {}", e);
        usage();
    });

    let mut hdl = PipesHandler {
        sel: 0,
        sessions: SessionContainer::new(settings.max_clients),
    };
    let s = Server::new("pipes", &mut hdl).expect("Unable to create service 'pipes'");
    hdl.sel = s.sel();

    REQHDL.set(
        RequestHandler::new_with(settings.max_clients, DEF_MSG_SIZE)
            .expect("Unable to create request handler"),
    );

    server_loop(|| {
        s.handle_ctrl_chan(&mut hdl)?;

        REQHDL.get().handle(|op, is| {
            match op {
                Operation::NEXT_IN => hdl.with_chan(is, |c, is| c.next_in(is)),
                Operation::NEXT_OUT => hdl.with_chan(is, |c, is| c.next_out(is)),
                Operation::COMMIT => hdl.with_chan(is, |c, is| c.commit(is)),
                Operation::REQ_NOTIFY => hdl.with_chan(is, |c, is| c.request_notify(is)),
                Operation::CLOSE | Operation::CLOSE_PIPE => {
                    let sid = is.label() as SessId;
                    // reply before we destroy the client's sgate. otherwise the client might
                    // notice the invalidated sgate before getting the reply and therefore give
                    // up before receiving the reply a bit later anyway. this in turn causes
                    // trouble if the receive gate (with the reply) is reused for something else.
                    is.reply_error(Code::Success).ok();
                    hdl.close_sess(sid, is.rgate())
                },
                Operation::STAT => hdl.with_chan(is, |c, is| c.stat(is)),
                Operation::SEEK => Err(Error::new(Code::SeekPipe)),
                Operation::GET_HASH => Err(Error::new(Code::NotSup)),
                _ => Err(Error::new(Code::InvArgs)),
            }
        })
    })
    .ok();

    Ok(())
}
