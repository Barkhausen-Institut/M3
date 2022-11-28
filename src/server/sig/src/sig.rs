/*
 * Copyright (C) 2022 Nils Asmussen, Barkhausen Institut
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

use m3::cap::Selector;
use m3::cell::LazyReadOnlyCell;
use m3::col::ToString;
use m3::com::{GateIStream, RecvGate, SGateArgs, SendGate};
use m3::errors::{Code, Error};
use m3::kif;
use m3::log;
use m3::reply_vmsg;
use m3::server::{
    server_loop, CapExchange, Handler, RequestHandler, Server, SessId, SessionContainer,
    DEF_MAX_CLIENTS,
};
use m3::session::{sig, ServerSession};
use m3::tcu::Label;

pub const LOG_DEF: bool = true;

static REQHDL: LazyReadOnlyCell<RequestHandler> = LazyReadOnlyCell::default();

#[derive(Debug)]
struct SigSession {
    crt: usize,
    _sess: ServerSession,
    _sgate: Option<SendGate>,
}

impl Handler<SigSession> for SigHandler {
    fn sessions(&mut self) -> &mut m3::server::SessionContainer<SigSession> {
        &mut self.sessions
    }

    fn open(
        &mut self,
        crt: usize,
        srv_sel: Selector,
        _arg: &str,
    ) -> Result<(Selector, SessId), Error> {
        self.sessions
            .add_next(crt, srv_sel, false, |sess| Ok(Self::new_sess(crt, sess)))
    }

    fn obtain(&mut self, crt: usize, sid: SessId, xchg: &mut CapExchange<'_>) -> Result<(), Error> {
        let op: sig::Operation = xchg.in_args().pop()?;
        log!(LOG_DEF, "[{}] sig::obtain(crt={}, op={})", sid, crt, op);

        if xchg.in_caps() != 1 {
            return Err(Error::new(Code::InvArgs));
        }

        let sess = self.sessions.get_mut(sid).unwrap();

        let sel = match op {
            sig::Operation::GET_SGATE => {
                if sess._sgate.is_some() {
                    return Err(Error::new(Code::Exists));
                }

                let sgate = SendGate::new_with(
                    SGateArgs::new(REQHDL.get().recv_gate())
                        .label(sid as Label)
                        .credits(1),
                )?;
                let sel = sgate.sel();
                sess._sgate = Some(sgate);
                sel
            },
            _ => return Err(Error::new(Code::InvArgs)),
        };

        xchg.out_caps(kif::CapRngDesc::new(kif::CapType::OBJECT, sel, 1));
        Ok(())
    }

    fn close(&mut self, _crt: usize, sid: SessId) {
        self.close_sess(sid, REQHDL.get().recv_gate()).ok();
    }
}

struct SigHandler {
    sel: Selector,
    sessions: SessionContainer<SigSession>,
}

impl SigHandler {
    fn new_sess(crt: usize, sess: ServerSession) -> SigSession {
        log!(crate::LOG_DEF, "[{}] sig::new()", sess.ident());
        SigSession {
            crt,
            _sess: sess,
            _sgate: None,
        }
    }

    fn close_sess(&mut self, sid: SessId, rgate: &RecvGate) -> Result<(), Error> {
        let sess = self
            .sessions
            .get_mut(sid)
            .ok_or_else(|| Error::new(Code::NotFound))?;

        log!(crate::LOG_DEF, "[{}] sig::close()", sid);

        // remove session
        let crt = sess.crt;
        self.sessions.remove(crt, sid);

        // ignore all potentially outstanding messages of this session
        rgate.drop_msgs_with(sid as Label).unwrap();
        Ok(())
    }

    fn quote(&mut self, is: &mut GateIStream<'_>) -> Result<(), Error> {
        let sid = is.label();
        let req: sig::QuoteReq = is.pop()?;

        log!(
            crate::LOG_DEF,
            "[{}] sig::quote(app={}, cfg={})",
            sid,
            req.app,
            req.cfg
        );

        // TODO generate quote
        let quote = "foo".to_string();

        reply_vmsg!(is, Code::Success, sig::QuoteReply { quote })
    }
}

#[no_mangle]
pub fn main() -> Result<(), Error> {
    let mut hdl = SigHandler {
        sel: 0,
        sessions: SessionContainer::new(DEF_MAX_CLIENTS),
    };

    let s = Server::new("sig", &mut hdl).expect("Unable to create service 'sig'");
    hdl.sel = s.sel();

    REQHDL.set(RequestHandler::new().expect("Unable to create request handler"));

    server_loop(|| {
        s.handle_ctrl_chan(&mut hdl)?;

        REQHDL.get().handle(|op, is| match op {
            sig::Operation::QUOTE => hdl.quote(is),
            _ => Err(Error::new(Code::InvArgs)),
        })
    })
    .ok();

    Ok(())
}
