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
use crate::cell::RefCell;
use crate::client::{ClientSession, HashInput, HashOutput, HashSession, MapFlags, Pager};
use crate::col::{String, ToString};
use crate::com::recv_result;
use crate::com::GateIStream;
use crate::com::{opcodes, EpMng, RecvGate, SendCap, SendGate, EP};
use crate::errors::{Code, Error};
use crate::io::{LogFlags, Read, Write};
use crate::kif::{CapRngDesc, CapType, Perm, INVALID_SEL};
use crate::log;
use crate::mem::{GlobOff, VirtAddr};
use crate::rc::Rc;
use crate::serialize::{M3Deserializer, M3Serializer, VecSink};
use crate::tcu::EpId;
use crate::tcu::TCU;
use crate::tiles::{Activity, ChildActivity};
use crate::util::math;
use crate::vfs::{filetable, Fd, File, FileEvent, FileInfo, Map, OpenFlags, Seek, SeekMode, TMode};

const NOTIFY_MSG_SIZE: usize = 64;

struct NonBlocking {
    notify_rgate: Box<RecvGate>,
    _notify_sgate: Box<SendCap>,
    notify_received: FileEvent,
    notify_requested: FileEvent,
}

enum LazySGate {
    Own(Selector),
    OwnAct(SendGate),
    Session(Rc<SendGate>),
}

impl LazySGate {
    fn activate_on(&mut self, sep: EP) -> Result<(), Error> {
        match self {
            Self::Own(sel) => {
                *self = Self::OwnAct(SendCap::new_bind(*sel).activate_on(sep)?);
                Ok(())
            },
            _ => Err(Error::new(Code::InvState)),
        }
    }

    fn get(&mut self) -> Result<&SendGate, Error> {
        if let Self::Own(src) = *self {
            *self = Self::OwnAct(SendGate::new_bind(src)?);
        }

        match self {
            Self::OwnAct(ref sg) => Ok(sg),
            Self::Session(sg) => Ok(&*sg),
            _ => unreachable!(),
        }
    }
}

/// A file implementation based on the *file protocol*
///
/// `GenericFile` implements the file protocol and can therefore be used for m3fs files, pipes,
/// virtual terminals, and whatever else provides file-like objects in the future.
///
/// # File protocol
///
/// The file protocol is a client/server protocol where the server provides clients direct access to
/// the data via their TCU. The following provides an overview:
///
/// ```text
/// +-------------------+           +-------------------+
/// |                   |           |                   |
/// |       Client      |           |       Server      |
/// |                   |           |                   |
/// |  +-------------+  |  request  |  +-------------+  |
/// |  |             +==+===========+=>|             |  |
/// |  |     TCU     |  |           |  |     TCU     |  |
/// |  |             |<=+===========+==+             |  |
/// |  +---+---------+  | response  |  +-------------+  |
/// |      |            |           |                   |
/// +------+------------+           +-------------------+
///        |
///        | data access
///        |
/// +------+--------------------------------------------+
/// |      v          +-----+     +-------+        DRAM |
/// |    +-+-----+    |  D3 |     |  D2   |             |
/// |    |  D1   |    +-----+     +-------+             |
/// |    +-------+                                      |
/// +---------------------------------------------------+
/// ```
///
/// As illustrated above, there are two types of channels: a message-passing channel between client
/// and server (shown as `==>`) and a memory channel of the client to the data in memory (shown as
/// `-->`). The data does not have to be contiguous in memory as the client can obtain access to
/// multiple and variably sized pieces (`D1`, `D2`, and `D3`) step by step. Access to the pieces of
/// data is requested by the client via the message-passing channel. The server is expected to
/// update the memory channel at the client side accordingly. Additionally, the server can instruct
/// clients to consider only a subset of the data visible via the memory channel. The server
/// therefore tells the client the offset and length of the subset, called *chunk*.
///
/// In more detail, the mandatory requests each server needs to support are:
/// - [`NextIn`](`opcodes::File::NextIn`): requests access to the next chunk of data to read. The
///   server is expected to update the memory channel (if required) and reply the offset and length
///   of the current chunk. The `NextIn` request also implicitly acknowledges that the client is
///   done with the previous chunk.
/// - [`NextOut`](`opcodes::File::NextOut`): requests access to the location where the next chunk of
///   data should be written to. Otherwise, it works analogously to `NextIn`.
/// - [`Commit`](`opcodes::File::Commit`): explicitly acknowledges the completion up to a specified
///   offset of the previous chunk. In case a client did not read or write the complete chunk, the
///   `Commit` should be used to inform the server. For example, if an application appends data to a
///   file and got access to a chunk of 1 MiB to do so, but only wrote 512 KiB, the client has to
///   inform the file system about the amount of data that was actually appended to the file.
///
/// Besides these mandatory requests, servers can optionally also support others like
/// [`Seek`](`opcodes::File::Seek`) or [`FStat`](`opcodes::File::FStat`).
pub struct GenericFile {
    id: Option<usize>,
    fs_id: Option<usize>,
    fd: Fd,
    flags: OpenFlags,
    sess: ClientSession,
    sgate: RefCell<LazySGate>,
    memep: Option<EP>,
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
            sess: ClientSession::new_owned_bind(sel),
            sgate: RefCell::new(LazySGate::Own(sel + 1)),
            memep: None,
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
    ) -> Result<Self, Error> {
        Ok(GenericFile {
            id: Some(id),
            fs_id: Some(fs_id),
            fd: filetable::INV_FD,
            flags,
            sess: ClientSession::new_bind(sel),
            sgate: RefCell::new(LazySGate::Session(sgate)),
            memep: Some(EP::new_bind(mep, INVALID_SEL)),
            delegated_ep: INVALID_SEL,
            blocking: true,
            nb_state: None,
            goff: 0,
            off: 0,
            pos: 0,
            len: 0,
            writing: false,
        })
    }

    fn file_id(&self) -> usize {
        self.id.unwrap_or(0)
    }

    pub(crate) fn unserialize(s: &mut M3Deserializer<'_>) -> Box<dyn File> {
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
            log!(
                LogFlags::LibFS,
                "GenFile[{}]::commit({}, {})",
                self.fd,
                if self.writing { "write" } else { "read" },
                self.pos,
            );

            send_recv_res!(
                self.sgate.borrow_mut().get()?,
                RecvGate::def(),
                opcodes::File::Commit,
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

    fn delegate_ep(&mut self, ep_sel: Selector, id: EpId) -> Result<(), Error> {
        if ep_sel != self.delegated_ep {
            log!(LogFlags::LibFS, "GenFile[{}]::delegate_ep({})", self.fd, id);

            self.submit(true)?;
            let crd = CapRngDesc::new(CapType::Object, ep_sel, 1);
            self.sess
                .delegate(crd, |s| s.push(opcodes::File::SetDest), |_| Ok(()))?;
            self.delegated_ep = ep_sel;
        }
        Ok(())
    }

    fn delegate_own_ep(&mut self) -> Result<(), Error> {
        if self.memep.is_none() {
            self.memep = Some(EpMng::get().acquire(0)?);
        }

        let (ep_sel, ep_id) = {
            let ep = self.memep.as_ref().unwrap();
            (ep.sel(), ep.id())
        };
        self.delegate_ep(ep_sel, ep_id)
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
                self.sgate.borrow_mut().get()?,
                RecvGate::def(),
                opcodes::File::NextIn,
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
                self.sgate.borrow_mut().get()?,
                RecvGate::def(),
                opcodes::File::NextOut,
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

        let notify_rgate = Box::new(RecvGate::new(
            math::next_log2(NOTIFY_MSG_SIZE),
            math::next_log2(NOTIFY_MSG_SIZE),
        )?);
        let _notify_sgate = Box::new(SendCap::new(&*notify_rgate)?);

        let crd = CapRngDesc::new(CapType::Object, _notify_sgate.sel(), 1);
        self.sess
            .delegate(crd, |s| s.push(opcodes::File::EnableNotify), |_| Ok(()))?;

        log!(
            LogFlags::LibFS,
            "GenFile[{}]::enable_notifications()",
            self.fd
        );

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
        // don't request a new notification if we already received the event
        if nb.notify_received.contains(events) {
            return Ok(());
        }

        log!(
            LogFlags::LibFS,
            "GenFile[{}]::request_notification(want={:x}, have={:x})",
            self.fd,
            events,
            nb.notify_requested
        );

        if !nb.notify_requested.contains(events) {
            send_recv_res!(
                self.sgate.borrow_mut().get()?,
                RecvGate::def(),
                opcodes::File::ReqNotify,
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
            if let Ok(msg) = nb.notify_rgate.fetch() {
                let mut imsg = GateIStream::new(msg, &nb.notify_rgate);
                let events = FileEvent::from_bits_truncate(imsg.pop::<u32>()?);
                nb.notify_received |= events;
                nb.notify_requested &= !events;
                log!(
                    LogFlags::LibFS,
                    "GenFile[{}]::receive_notify() -> received {:x}",
                    self.fd,
                    events
                );
                // give credits back to sender
                imsg.reply_error(Code::Success)?;
            }
        }

        // now check again if we have received this event; if not, we would block
        if !nb.notify_received.contains(event) {
            return Ok(false);
        }

        // okay, event received; remove it and continue
        if fetch {
            log!(
                LogFlags::LibFS,
                "GenFile[{}]::receive_notify() -> fetched {:x}",
                self.fd,
                event
            );
            nb.notify_received &= !event;
        }
        Ok(true)
    }
}

impl Drop for GenericFile {
    fn drop(&mut self) {
        // without new session, there is nothing to do as we have gotten the EP from somewhere else
        if self.flags.contains(OpenFlags::NEW_SESS) {
            // with new session, we might have acquired a new EP from the EpMng, so we need to give
            // it back (and invalidate it).
            if let Some(ep) = self.memep.take() {
                EpMng::get().release(ep, true);
            }
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
        log!(LogFlags::LibFS, "GenFile[{}]::remove()", self.fd);

        // submit read/written data
        self.submit(false).ok();

        if !self.flags.contains(OpenFlags::NEW_SESS) {
            let file_id = self.id.unwrap();
            if let Some(fs) = Activity::own().mounts().get_by_id(self.fs_id.unwrap()) {
                fs.borrow_mut().close(file_id).ok();
            }
        }
        else {
            // give EP back to EpMng if we have acquired one
            if let Some(ep) = self.memep.take() {
                EpMng::get().release(ep, true);
            }
        }
    }

    fn stat(&self) -> Result<FileInfo, Error> {
        log!(LogFlags::LibFS, "GenFile[{}]::stat()", self.fd);

        send_vmsg!(
            self.sgate.borrow_mut().get()?,
            RecvGate::def(),
            opcodes::File::FStat,
            self.file_id()
        )?;
        let mut reply = recv_result(RecvGate::def(), Some(self.sgate.borrow_mut().get()?))?;
        reply.pop()
    }

    fn path(&self) -> Result<String, Error> {
        let mut reply = send_recv_res!(
            self.sgate.borrow_mut().get()?,
            RecvGate::def(),
            opcodes::File::GetPath,
            self.file_id()
        )?;
        let path = reply.pop()?;

        let mounts = Activity::own().mounts();
        let mount_path = mounts
            .path_of_id(self.fs_id.unwrap())
            .ok_or_else(|| Error::new(Code::NotFound))?;
        Ok(mount_path.to_string() + "/" + path)
    }

    fn truncate(&mut self, length: usize) -> Result<(), Error> {
        self.submit(false)?;

        let mut reply = send_recv_res!(
            self.sgate.borrow_mut().get()?,
            RecvGate::def(),
            opcodes::File::Truncate,
            self.file_id(),
            length
        )?;
        // reset position in case we were behind the truncated position
        self.goff = reply.pop()?;
        self.off = reply.pop()?;
        // we've lost access to the previous extent
        self.pos = 0;
        self.len = 0;
        Ok(())
    }

    fn get_tmode(&self) -> Result<TMode, Error> {
        let mut reply = send_recv_res!(
            self.sgate.borrow_mut().get()?,
            RecvGate::def(),
            opcodes::File::GetTMode,
            self.file_id()
        )?;
        reply.pop()
    }

    fn file_type(&self) -> u8 {
        b'F'
    }

    fn delegate(&self, act: &ChildActivity) -> Result<Selector, Error> {
        let crd = CapRngDesc::new(CapType::Object, self.sess.sel(), 2);
        self.sess.obtain_for(
            act.sel(),
            crd,
            |s| s.push(opcodes::File::CloneFile),
            |_| Ok(()),
        )?;
        Ok(self.sess.sel() + 2)
    }

    fn serialize(&self, s: &mut M3Serializer<VecSink<'_>>) {
        s.push(self.flags.bits());
        s.push(self.sess.sel());
        s.push(self.fs_id.unwrap_or(!0));
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

    fn attach(&mut self, sep: EP, mep: &EP) -> Result<(), Error> {
        self.sgate.borrow_mut().activate_on(sep)?;
        self.delegate_ep(mep.sel(), mep.id())
    }
}

impl Seek for GenericFile {
    fn seek(&mut self, mut off: usize, mut whence: SeekMode) -> Result<usize, Error> {
        log!(
            LogFlags::LibFS,
            "GenFile[{}]::seek({}, {:?})",
            self.fd,
            off,
            whence
        );

        self.submit(false)?;

        if whence == SeekMode::Cur {
            off += self.goff + self.off + self.pos;
            whence = SeekMode::Set;
        }

        if whence != SeekMode::End
            && self.pos < self.len
            && off > self.goff + self.off
            && off < self.goff + self.off + self.len
        {
            self.pos = off - (self.goff + self.off);
            return Ok(off);
        }

        let mut reply = send_recv_res!(
            self.sgate.borrow_mut().get()?,
            RecvGate::def(),
            opcodes::File::Seek,
            self.file_id(),
            off,
            whence
        )?;

        self.goff = reply.pop()?;
        self.off = reply.pop()?;
        self.pos = 0;
        self.len = 0;
        Ok(self.goff + off)
    }
}

impl Read for GenericFile {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.delegate_own_ep()?;

        log!(
            LogFlags::LibFS,
            "GenFile[{}]::read({}, pos={})",
            self.fd,
            buf.len(),
            self.off + self.pos
        );

        let amount = self.next_in(buf.len())?;
        if amount > 0 {
            TCU::read(
                self.memep.as_ref().unwrap().id(),
                buf.as_mut_ptr(),
                amount,
                (self.off + self.pos) as GlobOff,
            )?;
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
        log!(LogFlags::LibFS, "GenFile[{}]::sync()", self.fd,);

        self.flush().and_then(|_| {
            send_recv_res!(
                self.sgate.borrow_mut().get()?,
                RecvGate::def(),
                opcodes::File::Sync,
                self.file_id()
            )
            .map(|_| ())
        })
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.delegate_own_ep()?;

        log!(
            LogFlags::LibFS,
            "GenFile[{}]::write({}, pos={})",
            self.fd,
            buf.len(),
            self.off + self.pos
        );

        let amount = self.next_out(buf.len())?;
        if amount > 0 {
            TCU::write(
                self.memep.as_ref().unwrap().id(),
                buf.as_ptr(),
                amount,
                (self.off + self.pos) as GlobOff,
            )?;
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
        virt: VirtAddr,
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
        self.delegate_ep(sess.ep().sel(), sess.ep().id())?;

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
        self.delegate_ep(sess.ep().sel(), sess.ep().id())?;

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
