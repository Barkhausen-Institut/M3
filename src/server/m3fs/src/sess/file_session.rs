/*
 * Copyright (C) 2020-2022 Nils Asmussen, Barkhausen Institut
 * Copyright (C) 2019-2020, Tendsin Mende <tendsin@protonmail.com>
 * Copyright (C) 2018, Sebastian Reimers <sebastian.reimers@mailbox.tu-dresden.de>
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

use crate::buf::LoadLimit;
use crate::data::{ExtPos, Extent, INodeRef, InodeNo};
use crate::ops::inodes;
use crate::sess::M3FSSession;

use m3::{
    cap::Selector,
    col::{String, ToString, Vec},
    com::{GateIStream, RecvGate, SendGate},
    errors::{Code, Error},
    kif::{CapRngDesc, CapType, Perm, INVALID_SEL},
    server::{CapExchange, SessId},
    session::ServerSession,
    syscalls, tcu,
    vfs::{OpenFlags, SeekMode},
};

struct Entry {
    sel: Selector,
}

impl Drop for Entry {
    fn drop(&mut self) {
        // revoke all capabilities
        m3::tiles::Activity::own()
            .revoke(
                m3::kif::CapRngDesc::new(m3::kif::CapType::OBJECT, self.sel, 1),
                false,
            )
            .unwrap();
    }
}

struct CapContainer {
    caps: Vec<Entry>,
}

impl CapContainer {
    pub fn add(&mut self, sel: Selector) {
        self.caps.push(Entry { sel });
    }
}

pub struct FileSession {
    // current position (the one that the client has access to)
    cur_pos: ExtPos,   // extent position
    cur_extlen: usize, // length of the extent
    cur_bytes: usize,  // number of bytes
    cur_sel: Selector, // memory capability

    // next position (the one that the client gets access to next)
    next_pos: ExtPos,    // extent position
    next_fileoff: usize, // file position (global offset)

    load_limit: LoadLimit,

    // for an ongoing append
    appending: bool,
    append_ext: Option<Extent>,

    // capabilities
    capscon: CapContainer,
    epcap: Selector,
    _sgate: Option<SendGate>, // keep the send gate alive

    // the file the client has access to
    oflags: OpenFlags,
    filename: String,
    ino: InodeNo,

    // session information
    sess_sel: Selector,
    sess_creator: usize,
    session_id: SessId,
    meta_sess_id: SessId,
    parent_sess_id: Option<SessId>,
    child_sessions: Vec<SessId>,

    _server_session: Option<ServerSession>, // keep the server session alive
}

impl FileSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        srv_sel: Selector,
        crt: usize,
        parent_sess_id: Option<SessId>,
        file_sess_id: SessId,
        meta_sess_id: SessId,
        filename: &str,
        oflags: OpenFlags,
        ino: InodeNo,
        rgate: Option<&RecvGate>,
    ) -> Result<Self, Error> {
        // the server session for this file
        let sess_sel = if srv_sel == m3::kif::INVALID_SEL {
            srv_sel
        }
        else {
            m3::tiles::Activity::own().alloc_sels(2)
        };

        let _server_session = if srv_sel == m3::kif::INVALID_SEL {
            None
        }
        else {
            Some(ServerSession::new_with_sel(
                srv_sel,
                sess_sel,
                crt,
                file_sess_id as u64,
                false,
            )?)
        };

        let send_gate = if srv_sel == m3::kif::INVALID_SEL {
            None
        }
        else {
            Some(m3::com::SendGate::new_with(
                m3::com::SGateArgs::new(rgate.unwrap())
                    // use the session id as identifier
                    .label(file_sess_id as tcu::Label)
                    .credits(1)
                    .sel(sess_sel + 1),
            )?)
        };

        let fsess = FileSession {
            cur_pos: ExtPos::new(0, 0),
            cur_extlen: 0,
            cur_bytes: 0,
            cur_sel: m3::kif::INVALID_SEL,

            next_pos: ExtPos::new(0, 0),
            next_fileoff: 0,

            load_limit: LoadLimit::new(),

            appending: false,
            append_ext: None,

            capscon: CapContainer { caps: vec![] },
            epcap: m3::kif::INVALID_SEL,
            _sgate: send_gate,

            oflags,
            filename: filename.to_string(),
            ino,

            sess_sel,
            sess_creator: crt,
            session_id: file_sess_id,
            meta_sess_id,
            parent_sess_id,
            child_sessions: Vec::new(),

            _server_session,
        };

        crate::open_files_mut().add_sess(ino);

        Ok(fsess)
    }

    pub fn clone(
        &mut self,
        srv_sel: Selector,
        crt: usize,
        sid: SessId,
        data: &mut CapExchange<'_>,
        rgate: &RecvGate,
    ) -> Result<Self, Error> {
        log!(
            crate::LOG_SESSION,
            "[{}] file::clone(path={})",
            self.session_id,
            self.filename
        );

        let nsess = Self::new(
            srv_sel,
            crt,
            Some(self.session_id),
            sid,
            self.meta_sess_id,
            &self.filename,
            self.oflags,
            self.ino,
            Some(rgate),
        )?;

        self.child_sessions.push(sid);

        data.out_caps(CapRngDesc::new(CapType::OBJECT, nsess.sess_sel, 2));

        Ok(nsess)
    }

    pub fn get_mem(&mut self, data: &mut CapExchange<'_>) -> Result<(), Error> {
        let offset: u32 = data.in_args().pop()?;

        log!(
            crate::LOG_SESSION,
            "[{}] file::get_mem(path={}, offset={})",
            self.session_id,
            self.filename,
            offset
        );

        let inode = inodes::get(self.ino)?;

        // determine extent from byte offset
        let (_, extpos) = inodes::get_seek_pos(&inode, offset as usize, SeekMode::SET)?;

        let sel = m3::tiles::Activity::own().alloc_sel();
        let (len, _) = inodes::get_extent_mem(
            &inode,
            &extpos,
            Perm::from(self.oflags),
            sel,
            &mut self.load_limit,
        )?;

        data.out_caps(m3::kif::CapRngDesc::new(CapType::OBJECT, sel, 1));
        data.out_args().push_word(0);
        data.out_args().push_word(len as u64);

        log!(
            crate::LOG_SESSION,
            "[{}] file::get_mem(path={}, offset={}) -> {}",
            self.session_id,
            self.filename,
            offset,
            len,
        );

        self.capscon.add(sel);

        Ok(())
    }

    fn revoke_cap(&mut self) {
        if self.cur_sel != m3::kif::INVALID_SEL {
            m3::tiles::Activity::own()
                .revoke(
                    m3::kif::CapRngDesc::new(m3::kif::CapType::OBJECT, self.cur_sel, 1),
                    false,
                )
                .unwrap();
            self.cur_sel = m3::kif::INVALID_SEL;
        }
    }

    pub fn set_ep(&mut self, ep: Selector) {
        self.epcap = ep;
    }

    pub fn ino(&self) -> InodeNo {
        self.ino
    }

    pub fn meta_sess(&self) -> SessId {
        self.meta_sess_id
    }

    pub fn child_sessions(&self) -> &[SessId] {
        &self.child_sessions
    }

    pub fn parent_sess(&self) -> Option<SessId> {
        self.parent_sess_id
    }

    pub fn remove_child(&mut self, id: SessId) {
        self.child_sessions.retain(|s| *s != id);
    }

    pub fn caps(&self) -> CapRngDesc {
        CapRngDesc::new(CapType::OBJECT, self.sess_sel, 2)
    }

    pub fn file_in_out(&mut self, is: &mut GateIStream<'_>, out: bool) -> Result<(), Error> {
        log!(
            crate::LOG_SESSION,
            "[{}] file::next_{}(); file[path={}, fileoff={}, pos={:?}]",
            self.session_id,
            if out { "out" } else { "in" },
            self.filename,
            self.next_fileoff,
            self.next_pos,
        );

        if (out && !self.oflags.contains(OpenFlags::W))
            || (!out && !self.oflags.contains(OpenFlags::R))
        {
            return Err(Error::new(Code::NoPerm));
        }

        let inode = inodes::get(self.ino)?;

        // in/out implicitly commits the previous in/out request
        if out && self.appending {
            self.commit_append(&inode, self.cur_bytes)?;
        }

        let mut sel = m3::tiles::Activity::own().alloc_sel();

        // do we need to append to the file?
        let (len, extlen) = if out && (self.next_fileoff as u64 == inode.size) {
            let mut files = crate::open_files_mut();
            let open_file = files.get_file_mut(self.ino).unwrap();

            if open_file.appending() {
                log!(
                    crate::LOG_SESSION,
                    "[{}] file::next_in_out(): append already in progress!",
                    self.session_id,
                );
                return Err(Error::new(Code::Exists));
            }

            // continue in last extent, if there is space
            if (self.next_pos.ext > 0)
                && (self.next_fileoff as u64 == inode.size)
                && ((self.next_fileoff % crate::superblock().block_size as usize) != 0)
            {
                let (fileoff, extpos) = inodes::get_seek_pos(&inode, 0, SeekMode::END)?;
                self.next_fileoff = fileoff;
                self.next_pos = extpos;
            }

            let (len, extlen, new_ext) = inodes::req_append(
                &inode,
                &self.next_pos,
                sel,
                Perm::from(self.oflags),
                &mut self.load_limit,
            )?;

            self.appending = true;
            self.append_ext = new_ext;

            open_file.set_appending(true);
            (len, extlen)
        }
        else {
            // get next mem_cap
            let res = inodes::get_extent_mem(
                &inode,
                &self.next_pos,
                Perm::from(self.oflags),
                sel,
                &mut self.load_limit,
            );
            match res {
                // if we didn't find the extent, turn that into EOF
                Err(e) if e.code() == Code::NotFound => (0, 0),
                Err(e) => return Err(e),
                Ok((len, extlen)) => (len, extlen),
            }
        };

        // The mem cap covers all blocks from `self.extoff` to `self.extoff + len`. Thus, the offset
        // to start is the offset within the first of these blocks
        let mut capoff = self.next_pos.off % crate::superblock().block_size as usize;
        if len > 0 {
            syscalls::activate(self.epcap, sel, INVALID_SEL, 0)?;

            // move forward
            self.cur_pos = self.next_pos;
            if (self.next_pos.off + len) >= extlen {
                self.next_pos.next_ext();
            }
            else {
                self.next_pos.off += len - capoff;
            }

            self.next_fileoff += len - capoff;
        }
        else {
            self.cur_pos = ExtPos::new(0, 0);
            capoff = 0;
            sel = m3::kif::INVALID_SEL;
        }

        self.cur_extlen = extlen;
        self.cur_bytes = len - capoff;

        log!(
            crate::LOG_SESSION,
            "[{}] file::next_{}() -> ({:?}, {})",
            self.session_id,
            if out { "out" } else { "in" },
            self.cur_pos,
            self.cur_bytes
        );

        reply_vmsg!(is, Code::None as u32, capoff, self.cur_bytes)?;

        self.revoke_cap();
        self.cur_sel = sel;

        Ok(())
    }

    pub fn file_seek(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        let off: usize = stream.pop()?;
        let whence = SeekMode::from(stream.pop::<u32>()?);

        log!(
            crate::LOG_SESSION,
            "[{}] file::seek(path={}, off={}, whence={})",
            self.session_id,
            self.filename,
            off,
            whence
        );

        if whence == SeekMode::CUR {
            return Err(Error::new(Code::InvArgs));
        }

        let inode = inodes::get(self.ino)?;
        let (pos, extpos) = inodes::get_seek_pos(&inode, off, whence)?;
        self.next_pos = extpos;
        self.next_fileoff = pos;

        reply_vmsg!(stream, Code::None as u32, pos - extpos.off, extpos.off)
    }

    pub fn file_stat(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        log!(
            crate::LOG_SESSION,
            "[{}] file::fstat(path={})",
            self.session_id,
            self.filename
        );

        let inode = inodes::get(self.ino)?;
        let info = inode.to_file_info();

        let mut reply = m3::mem::MsgBuf::borrow_def();
        reply.set(info.to_response());
        stream.reply(&reply)
    }

    pub fn file_path(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        log!(
            crate::LOG_SESSION,
            "[{}] file::get_path(path={})",
            self.session_id,
            self.filename
        );

        reply_vmsg!(stream, Code::None as u32, self.filename)
    }

    pub fn file_truncate(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        let off: usize = stream.pop()?;

        log!(
            crate::LOG_SESSION,
            "[{}] file::truncate(path={}, off={})",
            self.session_id,
            self.filename,
            off
        );

        let inode = inodes::get(self.ino)?;

        if off as u64 > inode.size {
            return Err(Error::new(Code::InvArgs));
        }

        let (fileoff, extpos) = inodes::get_seek_pos(&inode, off, SeekMode::SET)?;
        inodes::truncate(&inode, &extpos)?;

        // stay within the file bounds
        if self.next_fileoff > fileoff {
            self.next_fileoff = fileoff;
            self.next_pos = extpos;
        }

        // revoke the current to remove the client's access to now deleted parts
        // TODO we need to revoke the access from others as well, but clients are currently not
        // prepared for that!
        self.revoke_cap();

        reply_vmsg!(stream, Code::None as u32, fileoff - extpos.off)
    }

    pub fn file_commit(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        let nbytes: usize = stream.pop()?;

        log!(
            crate::LOG_SESSION,
            "[{}] file::commit(nbytes={}); file[path={}, fileoff={}, next={:?}]",
            self.session_id,
            nbytes,
            self.filename,
            self.next_fileoff,
            self.next_pos,
        );

        if (nbytes == 0) || (nbytes > self.cur_bytes) {
            return Err(Error::new(Code::InvArgs));
        }

        let inode = inodes::get(self.ino)?;

        let res = if self.appending {
            self.commit_append(&inode, nbytes)
        }
        else {
            if (self.next_pos.ext > self.cur_pos.ext)
                && ((self.cur_pos.off + nbytes) < self.cur_extlen)
            {
                self.next_pos.ext -= 1;
            }

            if nbytes < self.cur_bytes {
                self.next_pos.off = self.cur_pos.off + nbytes;
            }
            Ok(())
        };

        self.cur_bytes = 0;
        if let Err(e) = res {
            Err(e)
        }
        else {
            stream.reply_error(Code::None)
        }
    }

    fn commit_append(&mut self, inode: &INodeRef, submit: usize) -> Result<(), Error> {
        log!(
            crate::LOG_SESSION,
            "[{}] file::commit_append(inode={}, submit={})",
            self.session_id,
            inode.inode,
            submit
        );

        assert!(submit > 0, "commit_append() submit must be > 0");

        if !self.appending {
            return Ok(());
        }

        // adjust file position
        self.next_fileoff -= self.cur_bytes - submit;

        // add new extent?
        if let Some(ref mut append_ext) = self.append_ext.take() {
            let blocksize = crate::superblock().block_size as usize;
            let blocks = (submit + blocksize - 1) / blocksize;
            let old_len = append_ext.length;

            // append extent to file
            append_ext.length = blocks as u32;
            let new_ext = inodes::append_extent(inode, *append_ext)?;

            // free superfluous blocks
            if old_len as usize > blocks {
                crate::blocks_mut().free(
                    append_ext.start as usize + blocks,
                    old_len as usize - blocks,
                )?;
            }

            self.cur_extlen = blocks * blocksize;
            // have we appended the new extent to the previous extent?
            if !new_ext {
                self.next_pos.ext -= 1;
            }

            self.cur_pos = ExtPos::new(0, 0);
        }

        // we are at the end of the extent now, so move forward if not already done
        if self.next_pos.off >= self.cur_extlen {
            self.next_pos.next_ext();
        }

        // change size
        inode.as_mut().size += submit as u64;

        // stop appending
        let mut files = crate::open_files_mut();
        let ofile = files.get_file_mut(self.ino).unwrap();
        assert!(ofile.appending(), "ofile should be in append mode!");
        ofile.set_appending(false);

        self.append_ext = None;
        self.appending = false;

        Ok(())
    }

    pub fn file_sync(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        log!(crate::LOG_SESSION, "[{}] file::sync()", self.session_id,);

        crate::flush_buffer()?;
        stream.reply_error(Code::None)
    }
}

impl Drop for FileSession {
    fn drop(&mut self) {
        log!(
            crate::LOG_SESSION,
            "[{}] file::close(path={})",
            self.session_id,
            self.filename
        );

        // free to-be-appended blocks, if there are any
        if let Some(ext) = self.append_ext.take() {
            crate::blocks_mut()
                .free(ext.start as usize, ext.length as usize)
                .unwrap();
        }

        // remove session from open_files and from its meta session
        crate::open_files_mut().remove_session(self.ino).unwrap();

        // revoke caps if needed
        self.revoke_cap();
    }
}

impl M3FSSession for FileSession {
    fn creator(&self) -> usize {
        self.sess_creator
    }

    fn next_in(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        let _: usize = stream.pop()?;
        self.file_in_out(stream, false)
    }

    fn next_out(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        let _: usize = stream.pop()?;
        self.file_in_out(stream, true)
    }

    fn commit(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        let _fid: usize = stream.pop()?;
        self.file_commit(stream)
    }

    fn seek(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        let _fid: usize = stream.pop()?;
        self.file_seek(stream)
    }

    fn stat(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        let _: usize = stream.pop()?;
        self.file_stat(stream)
    }

    fn fstat(&mut self, _stream: &mut GateIStream<'_>) -> Result<(), Error> {
        Err(Error::new(Code::NotSup))
    }

    fn get_path(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        let _: usize = stream.pop()?;
        self.file_path(stream)
    }

    fn truncate(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        let _: usize = stream.pop()?;
        self.file_truncate(stream)
    }

    fn mkdir(&mut self, _stream: &mut GateIStream<'_>) -> Result<(), Error> {
        Err(Error::new(Code::NotSup))
    }

    fn rmdir(&mut self, _stream: &mut GateIStream<'_>) -> Result<(), Error> {
        Err(Error::new(Code::NotSup))
    }

    fn link(&mut self, _stream: &mut GateIStream<'_>) -> Result<(), Error> {
        Err(Error::new(Code::NotSup))
    }

    fn unlink(&mut self, _stream: &mut GateIStream<'_>) -> Result<(), Error> {
        Err(Error::new(Code::NotSup))
    }

    fn sync(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        let _: usize = stream.pop()?;
        self.file_sync(stream)
    }
}
