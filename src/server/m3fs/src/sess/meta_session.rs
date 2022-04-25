/*
 * Copyright (C) 2020-2022 Nils Asmussen, Barkhausen Institut
 * Copyright (C) 2019-2020, Tendsin Mende <tendsin@protonmail.com>
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

use crate::data::ExtPos;
use crate::ops::{dirs, inodes};
use crate::sess::{FileSession, M3FSSession};

use m3::{
    cap::Selector,
    cell::StaticCell,
    col::{Treap, Vec},
    com::{GateIStream, RecvGate, SGateArgs, SendGate},
    errors::{Code, Error},
    server::CapExchange,
    server::SessId,
    session::ServerSession,
    tcu::Label,
    vfs::{FileMode, OpenFlags},
};

static NEXT_PRIV_ID: StaticCell<SessId> = StaticCell::new(1);

pub struct MetaSession {
    _server_session: ServerSession,
    sgates: Vec<SendGate>,
    max_files: usize,
    files: Vec<SessId>,
    priv_files: Treap<SessId, FileSession>,
    priv_file_count: usize,
    priv_eps: Vec<Selector>,
    creator: usize,
    session_id: SessId,
}

impl MetaSession {
    pub fn new(
        _server_session: ServerSession,
        session_id: SessId,
        crt: usize,
        max_files: usize,
    ) -> Self {
        MetaSession {
            _server_session,
            sgates: Vec::new(),
            max_files,
            files: Vec::new(),
            priv_files: Treap::new(),
            priv_file_count: 0,
            priv_eps: Vec::new(),
            creator: crt,
            session_id,
        }
    }

    fn get_ep(&self, idx: usize) -> Result<Selector, Error> {
        self.priv_eps
            .get(idx)
            .copied()
            .ok_or_else(|| Error::new(Code::InvArgs))
    }

    pub fn add_ep(&mut self, ep: Selector) -> usize {
        self.priv_eps.push(ep);
        self.priv_eps.len() - 1
    }

    pub fn get_sgate(&mut self, data: &mut CapExchange<'_>, rgate: &RecvGate) -> Result<(), Error> {
        if data.in_caps() != 1 {
            return Err(Error::new(Code::InvArgs));
        }

        let sgate = SendGate::new_with(SGateArgs::new(rgate).label(self.session_id as Label))?;
        let sgate_selector = sgate.sel();
        self.sgates.push(sgate);

        data.out_caps(m3::kif::CapRngDesc::new(
            m3::kif::CapType::OBJECT,
            sgate_selector,
            1,
        ));

        Ok(())
    }

    pub fn file_sessions(&self) -> &[SessId] {
        &self.files
    }

    pub fn remove_file(&mut self, file_session: SessId) {
        self.files.retain(|sid| *sid != file_session);
    }

    /// Creates a file session based on this meta session for `file_session_id`.
    pub fn open_file(
        &mut self,
        selector: Selector,
        crt: usize,
        data: &mut CapExchange<'_>,
        file_session_id: SessId,
        rgate: &RecvGate,
    ) -> Result<FileSession, Error> {
        let flags = OpenFlags::from_bits_truncate(data.in_args().pop::<u32>()?);
        let path = data.in_args().pop_str_slice()?;

        log!(
            crate::LOG_SESSION,
            "[{}] meta::open(path={}, flags={:?})",
            self.session_id,
            path,
            flags
        );

        let session = self.do_open(selector, crt, path, flags, file_session_id, Some(rgate))?;

        self.files.push(file_session_id);

        data.out_caps(session.caps());

        log!(
            crate::LOG_SESSION,
            "[{}] meta::open(path={}, flags={:?}) -> inode={}, sid={}",
            self.session_id,
            path,
            flags,
            session.ino(),
            file_session_id,
        );

        Ok(session)
    }

    fn do_open(
        &mut self,
        srv: Selector,
        crt: usize,
        path: &str,
        flags: OpenFlags,
        file_session_id: SessId,
        rgate: Option<&RecvGate>,
    ) -> Result<FileSession, Error> {
        if self.files.len() + self.priv_file_count == self.max_files {
            return Err(Error::new(Code::NoSpace));
        }

        let ino = dirs::search(path, flags.contains(OpenFlags::CREATE))?;
        let inode = inodes::get(ino)?;
        let inode_mode = inode.mode;

        if (flags.contains(OpenFlags::W) && !inode_mode.contains(FileMode::IWUSR))
            || (flags.contains(OpenFlags::R) && !inode_mode.contains(FileMode::IRUSR))
        {
            log!(
                crate::LOG_SESSION,
                "insufficient permissions: flags={:o}, mode={:o}",
                flags,
                inode.mode,
            );
            return Err(Error::new(Code::NoPerm));
        }

        // only determine the current size, if we're writing and the file isn't empty
        if flags.contains(OpenFlags::TRUNC) {
            inodes::truncate(&inode, &ExtPos::new(0, 0))?;
            // TODO revoke access, if necessary
        }

        // for directories: ensure that we don't have a changed version in the cache
        if inode.mode.is_dir() {
            inodes::sync_metadata(&inode)?;
        }

        FileSession::new(
            srv,
            crt,
            None,
            file_session_id,
            self.session_id,
            path,
            flags,
            inode.inode,
            rgate,
        )
    }

    fn with_file_sess<F>(&mut self, stream: &mut GateIStream<'_>, func: F) -> Result<(), Error>
    where
        F: Fn(&mut FileSession, &mut GateIStream<'_>) -> Result<(), Error>,
    {
        let fid: usize = stream.pop()?;
        match self.priv_files.get_mut(&fid) {
            Some(f) => func(f, stream),
            None => Err(Error::new(Code::InvArgs)),
        }
    }
}

impl Drop for MetaSession {
    fn drop(&mut self) {
        for g in self.sgates.iter_mut() {
            g.deactivate();
        }
    }
}

impl M3FSSession for MetaSession {
    fn creator(&self) -> usize {
        self.creator
    }

    fn next_in(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        self.with_file_sess(stream, |f, stream| f.file_in_out(stream, false))
    }

    fn next_out(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        self.with_file_sess(stream, |f, stream| f.file_in_out(stream, true))
    }

    fn commit(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        self.with_file_sess(stream, |f, stream| f.file_commit(stream))
    }

    fn seek(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        self.with_file_sess(stream, |f, stream| f.file_seek(stream))
    }

    fn stat(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        self.with_file_sess(stream, |f, stream| f.file_stat(stream))
    }

    fn get_path(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        self.with_file_sess(stream, |f, stream| f.file_path(stream))
    }

    fn truncate(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        self.with_file_sess(stream, |f, stream| f.file_truncate(stream))
    }

    fn sync(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        self.with_file_sess(stream, |f, stream| f.file_sync(stream))
    }

    fn fstat(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        let path: &str = stream.pop()?;

        log!(
            crate::LOG_SESSION,
            "[{}] meta::stat(path={})",
            self.session_id,
            path
        );

        let ino = dirs::search(path, false)?;
        let inode = inodes::get(ino)?;

        let info = inode.to_file_info();

        let mut reply = m3::mem::MsgBuf::borrow_def();
        reply.set(info.to_response());
        stream.reply(&reply)
    }

    fn mkdir(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        let path: &str = stream.pop()?;
        let mode = FileMode::from_bits_truncate(stream.pop::<u16>()?) & FileMode::PERM;

        log!(
            crate::LOG_SESSION,
            "[{}] meta::mkdir(path={}, mode={:o})",
            self.session_id,
            path,
            mode
        );

        dirs::create(path, mode)?;

        stream.reply_error(Code::None)
    }

    fn rmdir(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        let path: &str = stream.pop()?;

        log!(
            crate::LOG_SESSION,
            "[{}] meta::rmdir(path={})",
            self.session_id,
            path
        );

        dirs::remove(path)?;

        stream.reply_error(Code::None)
    }

    fn link(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        let old_path: &str = stream.pop()?;
        let new_path: &str = stream.pop()?;

        log!(
            crate::LOG_SESSION,
            "[{}] meta::link(old_path={}, new_path: {})",
            self.session_id,
            old_path,
            new_path
        );

        dirs::link(old_path, new_path)?;

        stream.reply_error(Code::None)
    }

    fn unlink(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        let path: &str = stream.pop()?;

        log!(
            crate::LOG_SESSION,
            "[{}] meta::unlink(path={})",
            self.session_id,
            path
        );

        dirs::unlink(path, true)?;

        stream.reply_error(Code::None)
    }

    fn rename(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        let old_path: &str = stream.pop()?;
        let new_path: &str = stream.pop()?;

        log!(
            crate::LOG_SESSION,
            "[{}] meta::rename(old_path={}, new_path: {})",
            self.session_id,
            old_path,
            new_path
        );

        dirs::rename(old_path, new_path)?;

        stream.reply_error(Code::None)
    }

    fn open_priv(&mut self, stream: &mut GateIStream<'_>) -> Result<(), Error> {
        let path = stream.pop::<&str>()?;
        let flags = OpenFlags::from_bits_truncate(stream.pop::<u32>()?);
        let ep = stream.pop::<usize>()?;

        log!(
            crate::LOG_SESSION,
            "[{}] meta::open_priv(path={}, flags={:?}, ep={})",
            self.session_id,
            path,
            flags,
            ep
        );

        let ep_sel = self.get_ep(ep)?;

        let id = NEXT_PRIV_ID.get();
        let mut session = self.do_open(m3::kif::INVALID_SEL, 0, path, flags, id, None)?;
        session.set_ep(ep_sel);
        NEXT_PRIV_ID.set(id + 1);

        log!(
            crate::LOG_SESSION,
            "[{}] meta::open_priv(path={}, flags={:?}) -> inode={}, sid={}",
            self.session_id,
            path,
            flags,
            session.ino(),
            id,
        );

        self.priv_files.insert(id, session);
        self.priv_file_count += 1;

        reply_vmsg!(stream, 0, id)
    }

    fn close(&mut self, stream: &mut GateIStream<'_>) -> Result<bool, Error> {
        let fid = stream.pop::<SessId>()?;

        if self.priv_files.remove(&fid).is_some() {
            self.priv_file_count -= 1;
            stream.reply_error(Code::None)?;
        }
        else {
            stream.reply_error(Code::InvArgs)?;
        }
        Ok(false)
    }
}
