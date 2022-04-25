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
use core::cmp;
use core::fmt;

use crate::boxed::Box;
use crate::cap::Selector;
use crate::col::{String, ToString};
use crate::com::GateIStream;
use crate::com::{recv_reply, MemGate, RecvGate, SendGate, EP};
use crate::errors::{Code, Error};
use crate::goff;
use crate::int_enum;
use crate::io::{Read, Write};
use crate::kif::{CapRngDesc, CapType, Perm, INVALID_SEL};
use crate::math;
use crate::rc::Rc;
use crate::serialize::Source;
use crate::session::{ClientSession, HashInput, HashOutput, HashSession, MapFlags, Pager};
use crate::tcu::EpId;
use crate::tiles::{Activity, ChildActivity, StateSerializer};
use crate::vfs::{
    filetable, Fd, File, FileEvent, FileInfo, Map, OpenFlags, Seek, SeekMode, StatResponse,
};

int_enum! {
    /// The operations for [`GenericFile`].
    pub struct GenFileOp : u64 {
        const STAT          = 0;
        const SEEK          = 1;
        const NEXT_IN       = 2;
        const NEXT_OUT      = 3;
        const COMMIT        = 4;
        const TRUNCATE      = 5;
        const SYNC          = 6;
        const CLOSE         = 7;
        const CLONE         = 8;
        const GET_PATH      = 9;
        const SET_TMODE     = 10;
        const SET_DEST      = 11;
        const ENABLE_NOTIFY = 12;
        const REQ_NOTIFY    = 13;
    }
}

const NOTIFY_MSG_SIZE: usize = 64;

struct NonBlocking {
    notify_rgate: Box<RecvGate>,
    _notify_sgate: Box<SendGate>,
    notify_received: FileEvent,
    notify_requested: FileEvent,
}

/// A file implementation for all file-like objects.
///
/// `GenericFile` implements the file protocol and can therefore be used for m3fs files, pipes,
/// virtual terminals, and whatever else provides file-like objects in the future.
pub struct GenericFile {
    id: Option<usize>,
    fs_id: Option<usize>,
    fd: Fd,
    flags: OpenFlags,
    sess: ClientSession,
    sgate: Rc<SendGate>,
    mgate: MemGate,
    delegated_ep: Selector,
    blocking: bool,
    nb_state: Option<NonBlocking>,
    goff: usize,
    off: usize,
    pos: usize,
    len: usize,
    writing: bool,
}

impl GenericFile {
    pub(crate) fn new(flags: OpenFlags, sel: Selector, fs_id: Option<usize>) -> Self {
        GenericFile {
            id: None,
            fs_id,
            fd: filetable::INV_FD,
            flags,
            sess: ClientSession::new_bind(sel),
            sgate: Rc::new(SendGate::new_bind(sel + 1)),
            mgate: MemGate::new_bind(INVALID_SEL),
            delegated_ep: INVALID_SEL,
            blocking: true,
            nb_state: None,
            goff: 0,
            off: 0,
            pos: 0,
            len: 0,
            writing: false,
        }
    }

    pub(crate) fn new_without_sess(
        flags: OpenFlags,
        sel: Selector,
        id: usize,
        fs_id: usize,
        mep: EpId,
        sgate: Rc<SendGate>,
    ) -> Self {
        let mut mgate = MemGate::new_bind(INVALID_SEL);
        mgate.set_ep(Some(EP::new_bind(mep, INVALID_SEL)));
        GenericFile {
            id: Some(id),
            fs_id: Some(fs_id),
            fd: filetable::INV_FD,
            flags,
            sess: ClientSession::new_bind(sel),
            sgate,
            mgate,
            delegated_ep: INVALID_SEL,
            blocking: true,
            nb_state: None,
            goff: 0,
            off: 0,
            pos: 0,
            len: 0,
            writing: false,
        }
    }

    fn file_id(&self) -> usize {
        self.id.unwrap_or(0)
    }

    pub(crate) fn unserialize(s: &mut Source<'_>) -> Box<dyn File> {
        let flags: u32 = s.pop().unwrap();
        let sel: Selector = s.pop().unwrap();
        let fs_id: usize = s.pop().unwrap();
        Box::new(GenericFile::new(
            OpenFlags::from_bits_truncate(flags),
            sel,
            if fs_id == !0 { None } else { Some(fs_id) },
        ))
    }

    fn submit(&mut self, force: bool) -> Result<(), Error> {
        if self.pos > 0 && (self.writing || force) {
            send_recv_res!(
                &self.sgate,
                RecvGate::def(),
                GenFileOp::COMMIT,
                self.file_id(),
                self.pos
            )?;

            self.goff += self.pos;
            self.pos = 0;
            self.len = 0;
            self.writing = false;
        }
        Ok(())
    }

    fn delegate_ep(&mut self, ep_sel: Selector) -> Result<(), Error> {
        if ep_sel != self.delegated_ep {
            self.submit(true)?;
            let crd = CapRngDesc::new(CapType::OBJECT, ep_sel, 1);
            self.sess
                .delegate(crd, |s| s.push_word(GenFileOp::SET_DEST.val), |_| Ok(()))?;
            self.delegated_ep = ep_sel;
        }
        Ok(())
    }

    fn delegate_own_ep(&mut self) -> Result<(), Error> {
        self.mgate.activate()?;
        let ep_sel = self.mgate.ep().unwrap().sel();
        self.delegate_ep(ep_sel)
    }

    fn next_in(&mut self, len: usize) -> Result<usize, Error> {
        self.submit(false)?;
        if len == 0 {
            return Ok(0);
        }

        if self.pos == self.len {
            if !self.blocking && !self.receive_notify(FileEvent::INPUT, true)? {
                return Err(Error::new(Code::WouldBlock));
            }

            let mut reply = send_recv_res!(
                &self.sgate,
                RecvGate::def(),
                GenFileOp::NEXT_IN,
                self.file_id()
            )?;
            self.goff += self.len;
            self.off = reply.pop()?;
            self.len = reply.pop()?;
            self.pos = 0;
        }

        Ok(cmp::min(len, self.len - self.pos))
    }

    fn next_out(&mut self, len: usize) -> Result<usize, Error> {
        if len == 0 {
            return Ok(0);
        }

        if self.pos == self.len {
            if !self.blocking && !self.receive_notify(FileEvent::OUTPUT, true)? {
                return Err(Error::new(Code::WouldBlock));
            }

            let mut reply = send_recv_res!(
                &self.sgate,
                RecvGate::def(),
                GenFileOp::NEXT_OUT,
                self.file_id()
            )?;
            self.goff += self.len;
            self.off = reply.pop()?;
            self.len = reply.pop()?;
            self.pos = 0;
        }

        Ok(cmp::min(len, self.len - self.pos))
    }

    #[inline(never)]
    fn enable_notifications(&mut self) -> Result<(), Error> {
        if self.nb_state.is_some() {
            return Ok(());
        }

        let mut notify_rgate = Box::new(RecvGate::new(
            math::next_log2(NOTIFY_MSG_SIZE),
            math::next_log2(NOTIFY_MSG_SIZE),
        )?);
        notify_rgate.activate()?;
        let _notify_sgate = Box::new(SendGate::new(&notify_rgate)?);

        let crd = CapRngDesc::new(CapType::OBJECT, _notify_sgate.sel(), 1);
        self.sess.delegate(
            crd,
            |s| s.push_word(GenFileOp::ENABLE_NOTIFY.val),
            |_| Ok(()),
        )?;

        self.nb_state = Some(NonBlocking {
            notify_rgate,
            _notify_sgate,
            notify_received: FileEvent::empty(),
            notify_requested: FileEvent::empty(),
        });

        Ok(())
    }

    fn request_notification(&mut self, events: FileEvent) -> Result<(), Error> {
        let fid = self.file_id();
        let nb = self.nb_state.as_mut().unwrap();
        if !nb.notify_requested.contains(events) {
            send_recv_res!(
                &self.sgate,
                RecvGate::def(),
                GenFileOp::REQ_NOTIFY,
                fid,
                events.bits()
            )?;
            nb.notify_requested |= events;
        }
        Ok(())
    }

    #[inline(never)]
    fn receive_notify(&mut self, event: FileEvent, fetch: bool) -> Result<bool, Error> {
        // if we did not request a notification for this event yet, do that now
        if !self
            .nb_state
            .as_ref()
            .unwrap()
            .notify_requested
            .contains(event)
        {
            self.request_notification(event)?;
        }

        // if we did not receive the given event, check if there is a message
        let nb = self.nb_state.as_mut().unwrap();
        if !nb.notify_received.contains(event) {
            if let Some(msg) = nb.notify_rgate.fetch() {
                let mut imsg = GateIStream::new(msg, &nb.notify_rgate);
                let events = FileEvent::from_bits_truncate(imsg.pop::<u64>()?);
                nb.notify_received |= events;
                nb.notify_requested &= !events;
                // give credits back to sender
                imsg.reply_error(Code::None)?;
            }
        }

        // now check again if we have received this event; if not, we would block
        if !nb.notify_received.contains(event) {
            return Ok(false);
        }

        // okay, event received; remove it and continue
        if fetch {
            nb.notify_received &= !event;
        }
        Ok(true)
    }
}

impl Drop for GenericFile {
    fn drop(&mut self) {
        if !self.flags.contains(OpenFlags::NEW_SESS) {
            // we never want to invalidate the EP
            self.mgate.set_ep(None);
        }
    }
}

impl File for GenericFile {
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

    fn session(&self) -> Option<Selector> {
        Some(self.sess.sel())
    }

    fn remove(&mut self) {
        // submit read/written data
        self.submit(false).ok();

        if !self.flags.contains(OpenFlags::NEW_SESS) {
            let file_id = self.id.unwrap();
            if let Some(fs) = Activity::own().mounts().get_by_id(self.fs_id.unwrap()) {
                fs.borrow_mut().close(file_id);
            }
        }
        else {
            // revoke EP cap
            if let Some(ep) = self.mgate.ep() {
                Activity::own()
                    .revoke(CapRngDesc::new(CapType::OBJECT, ep.sel(), 1), true)
                    .ok();
            }
        }

        // file sessions are not known to our resource manager; thus close them manually
        send_recv_res!(
            &self.sgate,
            RecvGate::def(),
            GenFileOp::CLOSE,
            self.file_id()
        )
        .ok();
    }

    fn stat(&self) -> Result<FileInfo, Error> {
        send_vmsg!(
            &self.sgate,
            RecvGate::def(),
            GenFileOp::STAT,
            self.file_id()
        )?;
        let reply = recv_reply(RecvGate::def(), Some(&self.sgate))?;
        let resp = reply.msg().get_data::<StatResponse>();
        FileInfo::from_response(resp)
    }

    fn path(&self) -> Result<String, Error> {
        let mut reply = send_recv_res!(
            &self.sgate,
            RecvGate::def(),
            GenFileOp::GET_PATH,
            self.file_id()
        )?;
        let path = reply.pop()?;

        let mounts = Activity::own().mounts();
        let mount_path = mounts
            .path_of_id(self.fs_id.unwrap())
            .ok_or(Error::new(Code::NotFound))?;
        Ok(mount_path.to_string() + "/" + path)
    }

    fn truncate(&mut self, length: usize) -> Result<(), Error> {
        self.submit(false)?;

        let mut reply = send_recv_res!(
            &self.sgate,
            RecvGate::def(),
            GenFileOp::TRUNCATE,
            self.file_id(),
            length
        )?;
        // reset position in case we were behind the truncated position
        self.goff = reply.pop()?;
        // we've lost access to the previous extent
        self.pos = 0;
        self.len = 0;
        Ok(())
    }

    fn file_type(&self) -> u8 {
        b'F'
    }

    fn delegate(&self, act: &ChildActivity) -> Result<Selector, Error> {
        let crd = CapRngDesc::new(CapType::OBJECT, self.sess.sel(), 2);
        self.sess.obtain_for(
            act.sel(),
            crd,
            |s| s.push_word(GenFileOp::CLONE.val),
            |_| Ok(()),
        )?;
        Ok(self.sess.sel() + 2)
    }

    fn serialize(&self, s: &mut StateSerializer<'_>) {
        s.push_word(self.flags.bits() as u64);
        s.push_word(self.sess.sel());
        s.push_word(self.fs_id.unwrap_or(!0) as u64);
    }

    fn is_blocking(&self) -> bool {
        self.blocking
    }

    fn set_blocking(&mut self, blocking: bool) -> Result<(), Error> {
        if !blocking {
            self.enable_notifications()?;
        }
        self.blocking = blocking;
        Ok(())
    }

    fn fetch_signal(&mut self) -> Result<bool, Error> {
        self.enable_notifications()?;

        self.receive_notify(FileEvent::SIGNAL, true)
    }

    fn check_events(&mut self, events: FileEvent) -> bool {
        if self.blocking {
            true
        }
        else {
            self.receive_notify(events, false).unwrap()
        }
    }
}

impl Seek for GenericFile {
    fn seek(&mut self, mut off: usize, mut whence: SeekMode) -> Result<usize, Error> {
        self.submit(false)?;

        if whence == SeekMode::CUR {
            off += self.goff + self.pos;
            whence = SeekMode::SET;
        }

        if whence != SeekMode::END
            && self.pos < self.len
            && off > self.goff
            && off < self.goff + self.len
        {
            self.pos = off - self.goff;
            return Ok(off);
        }

        let mut reply = send_recv_res!(
            &self.sgate,
            RecvGate::def(),
            GenFileOp::SEEK,
            self.file_id(),
            off,
            whence
        )?;

        self.goff = reply.pop()?;
        let off: usize = reply.pop()?;
        self.pos = 0;
        self.len = 0;
        Ok(self.goff + off)
    }
}

impl Read for GenericFile {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.delegate_own_ep()?;

        let amount = self.next_in(buf.len())?;
        if amount > 0 {
            self.mgate
                .read(&mut buf[0..amount], (self.off + self.pos) as goff)?;
            self.pos += amount;
        }
        self.writing = false;
        Ok(amount)
    }
}

impl Write for GenericFile {
    fn flush(&mut self) -> Result<(), Error> {
        self.submit(false)
    }

    fn sync(&mut self) -> Result<(), Error> {
        self.flush().and_then(|_| {
            send_recv_res!(
                &self.sgate,
                RecvGate::def(),
                GenFileOp::SYNC,
                self.file_id()
            )
            .map(|_| ())
        })
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.delegate_own_ep()?;

        let amount = self.next_out(buf.len())?;
        if amount > 0 {
            self.mgate
                .write(&buf[0..amount], (self.off + self.pos) as goff)?;
            self.pos += amount;
        }
        self.writing = true;
        Ok(amount)
    }
}

impl Map for GenericFile {
    fn map(
        &self,
        pager: &Pager,
        virt: goff,
        off: usize,
        len: usize,
        prot: Perm,
        flags: MapFlags,
    ) -> Result<(), Error> {
        // TODO maybe check here whether self is a pipe and return an error?
        pager
            .map_ds(virt, len, off, prot, flags, &self.sess)
            .map(|_| ())
    }
}

impl HashInput for GenericFile {
    fn hash_input(&mut self, sess: &HashSession, len: usize) -> Result<usize, Error> {
        self.delegate_ep(sess.ep().sel())?;

        let mut remaining = len;
        while remaining > 0 {
            let amount = self.next_in(remaining)?;
            if amount == 0 {
                break;
            }

            sess.input(self.off + self.pos, amount)?;
            self.pos += amount;
            remaining -= amount;
        }
        Ok(len - remaining)
    }
}

impl HashOutput for GenericFile {
    fn hash_output(&mut self, sess: &HashSession, len: usize) -> Result<usize, Error> {
        self.delegate_ep(sess.ep().sel())?;

        let mut remaining = len;
        while remaining > 0 {
            let amount = self.next_out(remaining)?;
            if amount == 0 {
                break;
            }

            sess.output(self.off + self.pos, amount)?;
            self.pos += amount;
            remaining -= amount;
        }
        self.writing = true;
        Ok(len - remaining)
    }
}

impl fmt::Debug for GenericFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GenFile[flags={:?}, sess={}, goff={:#x}, off={:#x}, pos={:#x}, len={:#x}]",
            self.flags,
            self.sess.sel(),
            self.goff,
            self.off,
            self.pos,
            self.len
        )
    }
}
