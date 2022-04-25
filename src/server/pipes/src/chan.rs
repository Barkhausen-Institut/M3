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

use m3::cap::Selector;
use m3::cell::{Cell, RefCell};
use m3::com::{GateIStream, MemGate, RecvGate, SGateArgs, SendGate};
use m3::errors::{Code, Error};
use m3::kif;
use m3::log;
use m3::rc::Rc;
use m3::reply_vmsg;
use m3::server::SessId;
use m3::tcu::Label;
use m3::vfs::{FileEvent, FileInfo, FileMode};

use crate::pipe::{Flags, State};

#[derive(Copy, Clone, Debug)]
pub enum ChanType {
    READ,
    WRITE,
}

pub struct Channel {
    ty: ChanType,
    id: SessId,
    pipe: SessId,
    state: Rc<RefCell<State>>,
    mem: Option<MemGate>,
    sgate: SendGate,
    ep_cap: Option<Selector>,
    promised_events: Rc<Cell<FileEvent>>,
}

impl Channel {
    pub fn new(
        id: SessId,
        sel: Selector,
        ty: ChanType,
        pipe: SessId,
        state: Rc<RefCell<State>>,
        rgate: &RecvGate,
    ) -> Result<Self, Error> {
        let sgate = SendGate::new_with(
            SGateArgs::new(rgate)
                .label(id as Label)
                .credits(1)
                .sel(sel + 1),
        )?;
        Ok(Channel {
            ty,
            id,
            pipe,
            state,
            mem: None,
            sgate,
            ep_cap: None,
            promised_events: Rc::new(Cell::from(FileEvent::empty())),
        })
    }

    pub fn id(&self) -> SessId {
        self.id
    }

    pub fn ty(&self) -> ChanType {
        self.ty
    }

    pub fn pipe(&self) -> SessId {
        self.pipe
    }

    pub fn crd(&self) -> kif::CapRngDesc {
        kif::CapRngDesc::new(kif::CapType::OBJECT, self.sgate.sel() - 1, 2)
    }

    pub fn clone(&self, id: SessId, sel: Selector, rgate: &RecvGate) -> Result<Channel, Error> {
        Channel::new(id, sel, self.ty, self.pipe, self.state.clone(), rgate)
    }

    pub fn set_ep(&mut self, ep: Selector) {
        self.ep_cap = Some(ep);
    }

    pub fn enable_notify(&mut self, sgate: Selector) -> Result<(), Error> {
        if self.state.borrow_mut().get_notify_gate(self.id).is_some() {
            return Err(Error::new(Code::Exists));
        }

        self.state
            .borrow_mut()
            .enable_notify(self.id, sgate, self.promised_events.clone())
    }

    pub fn request_notify(&mut self, is: &mut GateIStream<'_>) -> Result<(), Error> {
        let _: usize = is.pop()?;
        let events: FileEvent = FileEvent::from_bits_truncate(is.pop()?);

        log!(
            crate::LOG_DEF,
            "[{}] pipes::request_notify(events={:?})",
            self.id,
            events
        );

        self.state.borrow_mut().request_notify(self.id, events)?;

        is.reply_error(Code::None)
    }

    pub fn next_in(&mut self, is: &mut GateIStream<'_>) -> Result<(), Error> {
        let _: usize = is.pop()?;

        log!(crate::LOG_DEF, "[{}] pipes::next_in()", self.id);

        let res = match self.ty {
            ChanType::READ => self.read(is, 0),
            ChanType::WRITE => Err(Error::new(Code::InvArgs)),
        };

        self.state.borrow_mut().handle_pending_writes(is.rgate());
        res
    }

    pub fn next_out(&mut self, is: &mut GateIStream<'_>) -> Result<(), Error> {
        let _: usize = is.pop()?;

        log!(crate::LOG_DEF, "[{}] pipes::next_out()", self.id);

        let res = match self.ty {
            ChanType::READ => Err(Error::new(Code::InvArgs)),
            ChanType::WRITE => self.write(is, 0),
        };

        self.state.borrow_mut().handle_pending_reads(is.rgate());
        res
    }

    pub fn commit(&mut self, is: &mut GateIStream<'_>) -> Result<(), Error> {
        let _fid: usize = is.pop()?;
        let nbytes: usize = is.pop()?;

        log!(
            crate::LOG_DEF,
            "[{}] pipes::commit(nbytes={})",
            self.id,
            nbytes
        );

        let res = match self.ty {
            ChanType::READ => self.read(is, nbytes),
            ChanType::WRITE => self.write(is, nbytes),
        };

        self.handle_pending(is.rgate());
        res
    }

    pub fn stat(&mut self, is: &mut GateIStream<'_>) -> Result<(), Error> {
        let info = FileInfo {
            mode: FileMode::IFCHR | FileMode::IRUSR | FileMode::IWUSR,
            ..Default::default()
        };

        let mut reply = m3::mem::MsgBuf::borrow_def();
        reply.set(info.to_response());
        is.reply(&reply)
    }

    pub fn close(&mut self, _sids: &mut [SessId], rgate: &RecvGate) -> Result<(), Error> {
        let res = match self.ty {
            ChanType::READ => self.close_reader(),
            ChanType::WRITE => self.close_writer(),
        };

        self.handle_pending(rgate);
        res
    }

    fn handle_pending(&mut self, rgate: &RecvGate) {
        match self.ty {
            ChanType::READ => self.state.borrow_mut().handle_pending_writes(rgate),
            ChanType::WRITE => self.state.borrow_mut().handle_pending_reads(rgate),
        }
    }

    fn read(&mut self, is: &mut GateIStream<'_>, commit: usize) -> Result<(), Error> {
        self.activate()?;

        // if a read is in progress, we have to commit it
        let mut state = self.state.borrow_mut();
        if let Some((last_id, last_amount)) = state.last_read {
            // if that wasn't the same client, queue the read request
            if last_id != self.id {
                // commits cannot be queued
                if commit > 0 {
                    return Err(Error::new(Code::InvArgs));
                }
                state.append_request(self.id, is, true);
                return Ok(());
            }

            // this client is the current reader, so commit the read by pulling it from the ringbuf
            let amount = if commit == 0 { last_amount } else { commit };
            log!(crate::LOG_DEF, "[{}] pipes::read_pull({})", self.id, amount);
            state.rbuf.pull(amount);
            state.last_read = None;
        }

        // commits are done here, because they don't get new data
        if commit > 0 {
            return reply_vmsg!(is, Code::None as u32, state.rbuf.size());
        }

        // if there are already queued read requests, just append this request
        if state.has_pending_reads() {
            // only queue the request if we still have writers
            if !state.flags().contains(Flags::WRITE_EOF) {
                state.append_request(self.id, is, true);
                return Ok(());
            }
        }

        // request new read position
        let amount = state.get_read_size();
        if let Some((pos, amount)) = state.rbuf.get_read_pos(amount) {
            // there is something to read; give client the position and size
            state.last_read = Some((self.id, amount));
            // okay, input is available, so we fulfilled our promise
            self.promised_events
                .set(self.promised_events.get() & !FileEvent::INPUT);
            log!(
                crate::LOG_DEF,
                "[{}] pipes::read(): {} @ {}",
                self.id,
                amount,
                pos
            );
            reply_vmsg!(is, Code::None as u32, pos, amount)
        }
        else {
            // nothing to read; if there is no writer left, report EOF
            if state.flags().contains(Flags::WRITE_EOF) {
                log!(crate::LOG_DEF, "[{}] pipes::read(): EOF", self.id);
                reply_vmsg!(is, Code::None as u32, 0usize, 0usize)
            }
            else {
                // if we promised the client that input would be available, report WouldBlock
                // instead of delaying the response.
                if self.promised_events.get().contains(FileEvent::INPUT) {
                    return Err(Error::new(Code::WouldBlock));
                }

                // otherwise queue the request
                state.append_request(self.id, is, true);
                Ok(())
            }
        }
    }

    fn write(&mut self, is: &mut GateIStream<'_>, commit: usize) -> Result<(), Error> {
        self.activate()?;

        // if there are no readers left, report EOF
        let mut state = self.state.borrow_mut();
        if state.flags().contains(Flags::READ_EOF) {
            log!(crate::LOG_DEF, "[{}] pipes::write(): EOF", self.id);
            return is.reply_error(Code::EndOfFile);
        }

        // is a write in progress?
        if let Some((last_id, last_amount)) = state.last_write {
            // if that wasn't the same client, queue the write request
            if last_id != self.id {
                // commits cannot be queued
                if commit > 0 {
                    return Err(Error::new(Code::InvArgs));
                }
                state.append_request(self.id, is, false);
                return Ok(());
            }

            // this client is the current reader, so commit the write by pushing it to the ringbuf
            let amount = if commit == 0 { last_amount } else { commit };
            log!(
                crate::LOG_DEF,
                "[{}] pipes::write_push({})",
                self.id,
                amount
            );
            state.rbuf.push(last_amount, amount);
            state.last_write = None;
        }

        // commits are done here, because they don't get new data
        if commit > 0 {
            return reply_vmsg!(is, Code::None as u32, state.rbuf.size());
        }

        // if there are already queued write requests, just append this request
        if state.has_pending_writes() {
            state.append_request(self.id, is, false);
            return Ok(());
        }

        // request new write position
        let amount = state.get_write_size();
        if let Some(pos) = state.rbuf.get_write_pos(amount) {
            // there is space to write; give client the position and size
            state.last_write = Some((self.id, amount));
            // okay, input is available, so we fulfilled our promise
            self.promised_events
                .set(self.promised_events.get() & !FileEvent::OUTPUT);
            log!(
                crate::LOG_DEF,
                "[{}] pipes::write(): {} @ {}",
                self.id,
                amount,
                pos
            );
            reply_vmsg!(is, Code::None as u32, pos, amount)
        }
        else {
            // if we promised the client that input would be available, report WouldBlock
            // instead of delaying the response.
            if self.promised_events.get().contains(FileEvent::OUTPUT) {
                return Err(Error::new(Code::WouldBlock));
            }

            // nothing to write, so queue the request
            state.append_request(self.id, is, false);
            Ok(())
        }
    }

    fn close_reader(&mut self) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        state.remove_pending(true, self.id);

        // if we're already at read-EOF, there is something wrong
        if state.flags().contains(Flags::READ_EOF) {
            return Err(Error::new(Code::InvArgs));
        }

        // is a read in progress?
        if let Some((last_id, _)) = state.last_read {
            // pull it from the ring buffer, if it's this client's read
            if last_id == self.id {
                log!(crate::LOG_DEF, "[{}] pipes::read_pull(): 0", self.id);
                state.rbuf.pull(0);
                state.last_read = None;
            }
            // otherwise, we ignore it because the client violated the protocol
        }

        // remove client
        let rd_left = state.remove_reader(self.id);
        if rd_left > 0 {
            log!(
                crate::LOG_DEF,
                "[{}] pipes::close(): rd-refs={}",
                self.id,
                rd_left
            );
            return Ok(());
        }

        // no readers left: EOF
        state.add_flags(Flags::READ_EOF);
        log!(crate::LOG_DEF, "[{}] pipes::close(): read EOF", self.id);
        Ok(())
    }

    fn close_writer(&mut self) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        state.remove_pending(false, self.id);

        // if we're already at write-EOF, there is something wrong
        if state.flags().contains(Flags::WRITE_EOF) {
            return Err(Error::new(Code::InvArgs));
        }

        // is a write in progress?
        if let Some((last_id, last_amount)) = state.last_write {
            // push it to the ring buffer, if it's this client's read
            if last_id == self.id {
                log!(crate::LOG_DEF, "[{}] pipes::write_push(): 0", self.id);
                state.rbuf.push(last_amount, 0);
                state.last_write = None;
            }
            // otherwise, we ignore it because the client violated the protocol
        }

        // remove client
        let wr_left = state.remove_writer(self.id);
        if wr_left > 0 {
            log!(
                crate::LOG_DEF,
                "[{}] pipes::close(): wr-refs={}",
                self.id,
                wr_left
            );
            return Ok(());
        }

        // no writers left: EOF
        state.add_flags(Flags::WRITE_EOF);
        log!(crate::LOG_DEF, "[{}] pipes::close(): write EOF", self.id);
        Ok(())
    }

    fn activate(&mut self) -> Result<(), Error> {
        // did we get an EP cap from the client?
        if let Some(ep_sel) = self.ep_cap.take() {
            assert!(self.mem.is_none());
            self.mem = Some(self.state.borrow().get_mem(self.id, self.ty, ep_sel)?);
        }
        Ok(())
    }
}
