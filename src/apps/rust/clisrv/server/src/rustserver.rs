/*
 * Copyright (C) 2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
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

#[macro_use]
extern crate m3;

use m3::errors::{Code, Error};
use m3::cap::Selector;
// use m3::cell::StaticCell;
use m3::col::String;
use m3::com::*;
use m3::kif;
use m3::session::ServerSession;
use m3::server::{Handler, Server, SessId, SessionContainer, server_loop};
use m3::util;

#[derive(Debug)]
struct MySession {
    sess: ServerSession,
    sgate: SendGate,
}

struct MyHandler {
    sessions: SessionContainer<MySession>,
    rgate: RecvGate,
}

int_enum! {
    struct Operation : u64 {
        const REVERSE_STRING = 0x0;
    }
}

impl Handler for MyHandler {
    fn open(&mut self, srv_sel: Selector, _arg: &str) -> Result<(Selector, u64), Error> {
        let sid = self.sessions.next_id();
        let sess = ServerSession::new(srv_sel, sid)?;
        let ident = self.sessions.next_id();
        let sgate = SendGate::new_with(
            SGateArgs::new(&self.rgate).label(ident).credits(256)
        )?;

        let sel = sess.sel();
        self.sessions.add(MySession {
            sess: sess,
            sgate: sgate,
        });
        Ok((sel, ident))
    }

    fn obtain(&mut self, sid: SessId, data: &mut kif::service::ExchangeData) -> Result<(), Error> {
        if data.args.count != 0 || data.caps != 1 {
            Err(Error::new(Code::InvArgs))
        }
        else {
            let sess = self.sessions.get(sid).unwrap();
            data.caps = kif::CapRngDesc::new(kif::CapType::OBJECT, sess.sgate.sel(), 1).value();
            Ok(())
        }
    }

    fn close(&mut self, sid: SessId) {
        self.sessions.remove(sid);
    }
}

impl MyHandler {
    pub fn new() -> Result<Self, Error> {
        let mut rgate = RecvGate::new(util::next_log2(256), util::next_log2(256))?;
        rgate.activate()?;
        Ok(MyHandler {
            sessions: SessionContainer::new(),
            rgate: rgate,
        })
    }

    pub fn handle(&mut self) -> Result<(), Error> {
        if let Some(mut is) = self.rgate.fetch() {
            match is.pop() {
                Operation::REVERSE_STRING   => Self::reverse_string(is),
                _                           => reply_vmsg!(is, Code::InvArgs as u64),
            }
        }
        else {
            Ok(())
        }
    }

    fn reverse_string(mut is: GateIStream) -> Result<(), Error> {
        let s: String = is.pop();
        let mut res = String::new();

        for i in s.chars().rev() {
            res.push(i);
        }

        reply_vmsg!(is, res)?;

        // pretend that we're crashing after a few requests
        // static COUNT: StaticCell<i32> = StaticCell::new(0);
        // if *COUNT >= 5 {
        //     return Err(Error::new(Code::EndOfFile));
        // }
        // COUNT.set(*COUNT + 1);

        Ok(())
    }
}

#[no_mangle]
pub fn main() -> i32 {
    let s = Server::new("test").expect("Unable to create service 'test'");

    let mut hdl = MyHandler::new().expect("Unable to create handler");

    server_loop(|| {
        s.handle_ctrl_chan(&mut hdl)?;

        hdl.handle()
    }).ok();

    0
}
