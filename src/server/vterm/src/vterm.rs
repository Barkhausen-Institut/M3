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

use m3::cap::Selector;
use m3::cell::{LazyReadOnlyCell, RefMut, StaticCell, StaticRefCell};
use m3::col::Vec;
use m3::com::{GateIStream, MemGate, Perm, RGateArgs, RecvGate, SGateArgs, SendGate, EP};
use m3::errors::{Code, Error};
use m3::int_enum;
use m3::io::{Serial, Write};
use m3::kif;
use m3::log;
use m3::rc::Rc;
use m3::reply_vmsg;
use m3::server::{
    server_loop, CapExchange, Handler, RequestHandler, Server, SessId, SessionContainer,
    DEF_MAX_CLIENTS,
};
use m3::session::ServerSession;
use m3::tcu::{Label, Message};
use m3::tiles::Activity;
use m3::vec;
use m3::vfs::{FileEvent, FileInfo, FileMode, GenFileOp};
use m3::{goff, send_vmsg};

pub const LOG_DEF: bool = false;
pub const LOG_INOUT: bool = false;

const BUF_SIZE: usize = 256;

int_enum! {
    struct Mode : u64 {
        const RAW       = 0;
        const COOKED    = 1;
    }
}

static REQHDL: LazyReadOnlyCell<RequestHandler> = LazyReadOnlyCell::default();
static BUFFER: StaticRefCell<Vec<u8>> = StaticRefCell::new(Vec::new());
static INPUT: StaticRefCell<Vec<u8>> = StaticRefCell::new(Vec::new());
static EOF: StaticCell<bool> = StaticCell::new(false);
static MODE: StaticCell<Mode> = StaticCell::new(Mode::COOKED);
static TMP_BUF: StaticRefCell<[u8; BUF_SIZE]> = StaticRefCell::new([0u8; BUF_SIZE]);

macro_rules! reply_vmsg_late {
    ( $msg:expr, $( $args:expr ),* ) => ({
        let mut msg = m3::mem::MsgBuf::borrow_def();
        m3::build_vmsg!(&mut msg, $( $args ),*);
        crate::REQHDL.get().recv_gate().reply(&msg, $msg)
    });
}

#[derive(Debug)]
struct VTermSession {
    crt: usize,
    sess: ServerSession,
    data: SessionData,
    parent: Option<SessId>,
    childs: Vec<SessId>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum SessionData {
    Meta,
    Chan(Channel),
}

#[derive(Debug)]
struct Channel {
    id: SessId,
    active: bool,
    writing: bool,
    ep: Option<Selector>,
    _sgate: SendGate,
    our_mem: Rc<MemGate>,
    notify_gates: Option<(RecvGate, SendGate)>,
    notify_events: FileEvent,
    pending_events: FileEvent,
    promised_events: FileEvent,
    pending_nextin: Option<&'static Message>,
    mem: MemGate,
    pos: usize,
    len: usize,
}

fn mem_off(id: SessId) -> goff {
    id as goff * BUF_SIZE as goff
}

impl Channel {
    fn new(id: SessId, mem: Rc<MemGate>, caps: Selector, writing: bool) -> Result<Self, Error> {
        let sgate = SendGate::new_with(
            SGateArgs::new(REQHDL.get().recv_gate())
                .label(id as Label)
                .credits(1)
                .sel(caps + 1),
        )?;
        let cmem = mem.derive(mem_off(id), BUF_SIZE, kif::Perm::RW)?;

        Ok(Channel {
            id,
            active: false,
            writing,
            ep: None,
            _sgate: sgate,
            our_mem: mem,
            notify_gates: None,
            notify_events: FileEvent::empty(),
            pending_events: FileEvent::empty(),
            promised_events: FileEvent::empty(),
            pending_nextin: None,
            mem: cmem,
            pos: 0,
            len: 0,
        })
    }

    fn activate(&mut self) -> Result<(), Error> {
        if !self.active {
            let sel = self.ep.ok_or_else(|| Error::new(Code::InvArgs))?;
            EP::new_bind(0, sel).configure(self.mem.sel())?;
            self.active = true;
        }
        Ok(())
    }

    fn set_tmode(&mut self, is: &mut GateIStream<'_>) -> Result<(), Error> {
        let _fid: usize = is.pop()?;
        let mode = is.pop::<Mode>()?;

        log!(
            crate::LOG_DEF,
            "[{}] vterm::set_tmode(mode={})",
            self.id,
            mode
        );
        MODE.set(mode);
        INPUT.borrow_mut().clear();

        is.reply_error(Code::None)
    }

    fn next_in(&mut self, is: &mut GateIStream<'_>) -> Result<(), Error> {
        let _: usize = is.pop()?;

        log!(crate::LOG_INOUT, "[{}] vterm::next_in()", self.id);

        if self.writing {
            return Err(Error::new(Code::NoPerm));
        }

        self.pos += self.len - self.pos;

        self.activate()?;

        if self.pos == self.len {
            let mut input = INPUT.borrow_mut();
            if !EOF.get() && input.is_empty() {
                // if we promised the client that input would be available, report WouldBlock
                // instead of delaying the response.
                if self.promised_events.contains(FileEvent::INPUT) {
                    return Err(Error::new(Code::WouldBlock));
                }

                assert!(self.pending_nextin.is_none());
                self.pending_nextin = Some(is.take_msg());
                return Ok(());
            }

            self.fetch_input(&mut input)?;
        }

        reply_vmsg!(is, Code::None as u32, self.pos, self.len - self.pos)
    }

    fn fetch_input(&mut self, input: &mut RefMut<'_, Vec<u8>>) -> Result<(), Error> {
        // okay, input is available, so we fulfilled our promise
        self.promised_events &= !FileEvent::INPUT;
        self.our_mem.write(input, mem_off(self.id))?;
        self.len = input.len();
        self.pos = 0;

        log!(
            crate::LOG_INOUT,
            "[{}] vterm::next_in() -> ({}, {})",
            self.id,
            self.pos,
            self.len - self.pos
        );

        EOF.set(false);
        input.clear();

        Ok(())
    }

    fn next_out(&mut self, is: &mut GateIStream<'_>) -> Result<(), Error> {
        let _: usize = is.pop()?;

        log!(crate::LOG_INOUT, "[{}] vterm::next_out()", self.id);

        if !self.writing {
            return Err(Error::new(Code::NoPerm));
        }

        self.flush(self.len)?;
        self.activate()?;

        self.pos = 0;
        self.len = BUF_SIZE;

        reply_vmsg!(is, Code::None as u32, 0usize, BUF_SIZE)
    }

    fn commit(&mut self, is: &mut GateIStream<'_>) -> Result<(), Error> {
        let _fid: usize = is.pop()?;
        let nbytes: usize = is.pop()?;

        log!(
            crate::LOG_INOUT,
            "[{}] vterm::commit(nbytes={})",
            self.id,
            nbytes
        );

        if nbytes > self.len - self.pos {
            return Err(Error::new(Code::InvArgs));
        }

        if self.writing {
            self.flush(nbytes)?;
        }
        else {
            self.pos += nbytes;
        }

        is.reply_error(Code::None)
    }

    fn stat(&mut self, is: &mut GateIStream<'_>) -> Result<(), Error> {
        let info = FileInfo {
            mode: FileMode::IFCHR | FileMode::IRUSR | FileMode::IWUSR,
            ..Default::default()
        };

        let mut reply = m3::mem::MsgBuf::borrow_def();
        reply.set(info.to_response());
        is.reply(&reply)
    }

    fn flush(&mut self, nbytes: usize) -> Result<(), Error> {
        if nbytes > 0 {
            self.our_mem
                .read(&mut TMP_BUF.borrow_mut()[0..nbytes], mem_off(self.id))?;
            Serial::new().write(&TMP_BUF.borrow()[0..nbytes])?;
        }
        self.len = 0;
        Ok(())
    }

    fn request_notify(&mut self, is: &mut GateIStream<'_>) -> Result<(), Error> {
        let _: usize = is.pop()?;
        let events: FileEvent = FileEvent::from_bits_truncate(is.pop()?);

        log!(
            crate::LOG_DEF,
            "[{}] vterm::req_notify(events={:?})",
            self.id,
            events
        );

        if self.notify_gates.is_none() {
            return Err(Error::new(Code::NotSup));
        }

        self.notify_events |= events;
        // remove from promised events, because we need to notify the client about them again first
        self.promised_events &= !events;
        // check whether input is available already
        if events.contains(FileEvent::INPUT) && !INPUT.borrow().is_empty() {
            self.pending_events |= FileEvent::INPUT;
        }
        // output is always possible
        if events.contains(FileEvent::OUTPUT) {
            self.pending_events |= FileEvent::OUTPUT;
        }
        // directly notify the client, if there is any input or output possible
        self.send_events();

        is.reply_error(Code::None)
    }

    fn add_event(&mut self, event: FileEvent) -> bool {
        if self.notify_events.contains(event) {
            log!(
                crate::LOG_DEF,
                "[{}] vterm::received_event({:?})",
                self.id,
                event
            );
            self.pending_events |= event;
            self.send_events();
            true
        }
        else {
            false
        }
    }

    fn send_events(&mut self) {
        if !self.pending_events.is_empty() {
            let (rg, sg) = self.notify_gates.as_ref().unwrap();
            if sg.credits().unwrap() > 0 {
                log!(
                    crate::LOG_DEF,
                    "[{}] vterm::sending_events({:?})",
                    self.id,
                    self.pending_events
                );
                // ignore errors
                send_vmsg!(sg, rg, self.pending_events.bits()).ok();
                // we promise the client that these operations will not block on the next call
                self.promised_events = self.pending_events;
                self.notify_events &= !self.pending_events;
                self.pending_events = FileEvent::empty();
            }
        }
    }
}

struct VTermHandler {
    sel: Selector,
    sessions: SessionContainer<VTermSession>,
    mem: Rc<MemGate>,
}

impl VTermHandler {
    fn new_sess(crt: usize, sess: ServerSession) -> VTermSession {
        log!(crate::LOG_DEF, "[{}] vterm::new_meta()", sess.ident());
        VTermSession {
            crt,
            sess,
            data: SessionData::Meta,
            parent: None,
            childs: Vec::new(),
        }
    }

    fn new_chan(
        &self,
        parent: SessId,
        crt: usize,
        sid: SessId,
        writing: bool,
    ) -> Result<VTermSession, Error> {
        log!(crate::LOG_DEF, "[{}] vterm::new_chan()", sid);
        let sels = Activity::own().alloc_sels(2);
        Ok(VTermSession {
            crt,
            sess: ServerSession::new_with_sel(self.sel, sels, crt, sid as u64, false)?,
            data: SessionData::Chan(Channel::new(sid, self.mem.clone(), sels, writing)?),
            parent: Some(parent),
            childs: Vec::new(),
        })
    }

    fn close_sess(&mut self, sid: SessId, rgate: &RecvGate) -> Result<(), Error> {
        // close this and all child sessions
        let mut sids = vec![sid];
        while let Some(id) = sids.pop() {
            if let Some(sess) = self.sessions.get_mut(id) {
                log!(crate::LOG_DEF, "[{}] vterm::close(): closing {}", sid, id);

                // close child sessions as well
                sids.extend_from_slice(&sess.childs);

                // remove session
                let parent = sess.parent.take();
                let crt = sess.crt;
                self.sessions.remove(crt, id);

                // remove us from parent
                if let Some(pid) = parent {
                    if let Some(p) = self.sessions.get_mut(pid) {
                        p.childs.retain(|cid| *cid != id);
                    }
                }

                // ignore all potentially outstanding messages of this session
                rgate.drop_msgs_with(id as Label);
            }
        }
        Ok(())
    }

    fn with_chan<F, R>(&mut self, is: &mut GateIStream<'_>, func: F) -> Result<R, Error>
    where
        F: Fn(&mut Channel, &mut GateIStream<'_>) -> Result<R, Error>,
    {
        let sess = self.sessions.get_mut(is.label() as SessId).unwrap();
        match &mut sess.data {
            SessionData::Meta => Err(Error::new(Code::InvArgs)),
            SessionData::Chan(c) => func(c, is),
        }
    }
}

impl Handler<VTermSession> for VTermHandler {
    fn sessions(&mut self) -> &mut m3::server::SessionContainer<VTermSession> {
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
        let op: GenFileOp = xchg.in_args().pop()?;
        log!(LOG_DEF, "[{}] vterm::obtain(crt={}, op={})", sid, crt, op);

        if xchg.in_caps() != 2 {
            return Err(Error::new(Code::InvArgs));
        }
        if !self.sessions.can_add(crt) {
            return Err(Error::new(Code::NoSpace));
        }

        let (nsid, nsess) = {
            let sessions = &self.sessions;
            let nsid = sessions.next_id()?;
            let sess = sessions.get(sid).unwrap();
            match &sess.data {
                SessionData::Meta => match op {
                    GenFileOp::CLONE => self
                        .new_chan(sid, crt, nsid, xchg.in_args().pop_word()? == 1)
                        .map(|s| (nsid, s)),
                    _ => Err(Error::new(Code::InvArgs)),
                },

                SessionData::Chan(c) => match op {
                    GenFileOp::CLONE => self.new_chan(sid, crt, nsid, c.writing).map(|s| (nsid, s)),
                    _ => Err(Error::new(Code::InvArgs)),
                },
            }
        }?;

        let sel = nsess.sess.sel();
        self.sessions.add(crt, nsid, nsess).unwrap();
        // remember that the new session is a child of the current one
        self.sessions.get_mut(sid).unwrap().childs.push(nsid);

        xchg.out_caps(kif::CapRngDesc::new(kif::CapType::OBJECT, sel, 2));
        Ok(())
    }

    fn delegate(
        &mut self,
        _crt: usize,
        sid: SessId,
        xchg: &mut CapExchange<'_>,
    ) -> Result<(), Error> {
        let op: GenFileOp = xchg.in_args().pop()?;
        log!(LOG_DEF, "[{}] vterm::delegate(op={})", sid, op);

        if xchg.in_caps() != 1 {
            return Err(Error::new(Code::InvArgs));
        }

        let sessions = &mut self.sessions;
        let sess = sessions.get_mut(sid).unwrap();
        match &mut sess.data {
            SessionData::Meta => Err(Error::new(Code::InvArgs)),
            SessionData::Chan(c) => match op {
                GenFileOp::SET_DEST => {
                    let sel = Activity::own().alloc_sel();
                    c.ep = Some(sel);
                    xchg.out_caps(kif::CapRngDesc::new(kif::CapType::OBJECT, sel, 1));
                    Ok(())
                },
                GenFileOp::ENABLE_NOTIFY => {
                    if c.notify_gates.is_some() {
                        return Err(Error::new(Code::Exists));
                    }

                    let sel = Activity::own().alloc_sel();
                    let mut rgate = RecvGate::new_with(RGateArgs::default().order(6).msg_order(6))?;
                    rgate.activate()?;
                    c.notify_gates = Some((rgate, SendGate::new_bind(sel)));
                    xchg.out_caps(kif::CapRngDesc::new(kif::CapType::OBJECT, sel, 1));
                    Ok(())
                },
                _ => Err(Error::new(Code::InvArgs)),
            },
        }
    }

    fn close(&mut self, _crt: usize, sid: SessId) {
        self.close_sess(sid, REQHDL.get().recv_gate()).ok();
    }
}

fn add_signal(hdl: &mut VTermHandler) {
    hdl.sessions.for_each(|s| match &mut s.data {
        SessionData::Chan(c) => {
            c.add_event(FileEvent::SIGNAL);
        },
        SessionData::Meta => {},
    });
}

fn add_input(hdl: &mut VTermHandler, eof: bool, mut flush: bool, input: &mut RefMut<'_, Vec<u8>>) {
    // pass to first session that wants input
    EOF.set(eof);

    hdl.sessions.for_each(|s| {
        if flush || !input.is_empty() {
            if let SessionData::Chan(c) = &mut s.data {
                if let Some(msg) = c.pending_nextin.take() {
                    c.fetch_input(input).unwrap();
                    reply_vmsg_late!(msg, Code::None as u32, c.pos, c.len - c.pos).unwrap();
                    flush = false;
                }
                else if c.add_event(FileEvent::INPUT) {
                    flush = false;
                }
            }
        }
    });
}

fn receive_acks(hdl: &mut VTermHandler) {
    hdl.sessions.for_each(|s| match &mut s.data {
        SessionData::Chan(c) => {
            if let Some((rg, _sg)) = &c.notify_gates {
                if let Some(msg) = rg.fetch() {
                    rg.ack_msg(msg).unwrap();
                    // try again to send events, if there are some
                    c.send_events();
                }
            }
        },
        SessionData::Meta => {},
    });
}

fn handle_input(hdl: &mut VTermHandler, msg: &'static Message) {
    let mut input = INPUT.borrow_mut();
    let mut buffer = BUFFER.borrow_mut();

    let bytes =
        unsafe { core::slice::from_raw_parts(msg.data.as_ptr(), msg.header.length as usize) };
    let mut flush = false;
    let mut eof = false;
    if MODE.get() == Mode::RAW {
        input.extend_from_slice(bytes);
    }
    else {
        let mut output = vec![];
        for b in bytes {
            match b {
                // ^D
                0x04 => eof = true,
                // ^C
                0x03 => add_signal(hdl),
                // backspace
                0x7f => {
                    output.push(0x08);
                    output.push(b' ');
                    output.push(0x08);
                    buffer.pop();
                },
                b => {
                    if *b == 27 {
                        buffer.push(b'^');
                        output.push(b'^');
                    }
                    else if *b == b'\n' {
                        flush = true;
                    }
                    if *b == b'\n' || !b.is_ascii_control() {
                        buffer.push(*b);
                    }
                },
            }

            if *b == b'\n' || !b.is_ascii_control() {
                output.push(*b);
            }
        }

        if eof || flush {
            input.extend_from_slice(&buffer);
            buffer.clear();
        }
        Serial::new().write(&output).unwrap();
    }

    add_input(hdl, eof, eof || flush, &mut input);
}

#[no_mangle]
pub fn main() -> i32 {
    let mut hdl = VTermHandler {
        sel: 0,
        sessions: SessionContainer::new(DEF_MAX_CLIENTS),
        mem: Rc::new(
            MemGate::new(DEF_MAX_CLIENTS * BUF_SIZE, Perm::RW).expect("Unable to alloc memory"),
        ),
    };

    let s = Server::new("vterm", &mut hdl).expect("Unable to create service 'vterm'");
    hdl.sel = s.sel();

    REQHDL.set(RequestHandler::default().expect("Unable to create request handler"));

    let sel = Activity::own().alloc_sel();
    let mut serial_gate = Activity::own()
        .resmng()
        .unwrap()
        .get_serial(sel)
        .expect("Unable to allocate serial rgate");
    serial_gate
        .activate()
        .expect("Unable to activate serial rgate");

    server_loop(|| {
        s.handle_ctrl_chan(&mut hdl)?;

        if let Some(msg) = serial_gate.fetch() {
            log!(crate::LOG_INOUT, "Got input message with {} bytes", {
                msg.header.length
            });
            handle_input(&mut hdl, msg);
            serial_gate.ack_msg(msg).unwrap();
        }

        receive_acks(&mut hdl);

        REQHDL.get().handle(|op, is| {
            match op {
                GenFileOp::NEXT_IN => hdl.with_chan(is, |c, is| c.next_in(is)),
                GenFileOp::NEXT_OUT => hdl.with_chan(is, |c, is| c.next_out(is)),
                GenFileOp::COMMIT => hdl.with_chan(is, |c, is| c.commit(is)),
                GenFileOp::CLOSE => {
                    let sid = is.label() as SessId;
                    // reply before we destroy the client's sgate. otherwise the client might
                    // notice the invalidated sgate before getting the reply and therefore give
                    // up before receiving the reply a bit later anyway. this in turn causes
                    // trouble if the receive gate (with the reply) is reused for something else.
                    is.reply_error(Code::None).ok();
                    hdl.close_sess(sid, is.rgate())
                },
                GenFileOp::STAT => hdl.with_chan(is, |c, is| c.stat(is)),
                GenFileOp::SEEK => Err(Error::new(Code::NotSup)),
                GenFileOp::SET_TMODE => hdl.with_chan(is, |c, is| c.set_tmode(is)),
                GenFileOp::REQ_NOTIFY => hdl.with_chan(is, |c, is| c.request_notify(is)),
                _ => Err(Error::new(Code::InvArgs)),
            }
        })
    })
    .ok();

    0
}
