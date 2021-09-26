/*
 * Copyright (C) 2015-2020, Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Copyright (C) 2019-2020, Tendsin Mende <tendsin@protonmail.com>
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

use crate::data::{ExtPos, FileMode};
use crate::ops::{dirs, inodes};
use crate::sess::{FileSession, M3FSSession};

use m3::{
    cap::Selector,
    col::Vec,
    com::{GateIStream, RecvGate, SendGate},
    errors::{Code, Error},
    server::CapExchange,
    server::SessId,
    session::ServerSession,
    vfs::OpenFlags,
};

pub struct MetaSession {
    _server_session: ServerSession,
    sgates: Vec<SendGate>,
    max_files: usize,
    files: Vec<SessId>,
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
            creator: crt,
            session_id,
        }
    }

    pub fn get_sgate(&mut self, data: &mut CapExchange, rgate: &RecvGate) -> Result<(), Error> {
        if data.in_caps() != 1 {
            return Err(Error::new(Code::InvArgs));
        }

        let sgate = SendGate::new(rgate)?;
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
        data: &mut CapExchange,
        file_session_id: SessId,
        rgate: &RecvGate,
    ) -> Result<FileSession, Error> {
        if self.files.len() == self.max_files {
            return Err(Error::new(Code::NoSpace));
        }

        let flags = OpenFlags::from_bits_truncate(data.in_args().pop::<u32>()?);
        let path = data.in_args().pop_str_slice()?;

        log!(
            crate::LOG_SESSION,
            "[{}] meta::open(path={}, flags={:?})",
            self.session_id,
            path,
            flags
        );

        let session = self.do_open(selector, crt, path, flags, file_session_id, rgate)?;

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
        rgate: &RecvGate,
    ) -> Result<FileSession, Error> {
        let ino = dirs::search(&path, flags.contains(OpenFlags::CREATE))?;
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

    fn next_in(&mut self, _stream: &mut GateIStream) -> Result<(), Error> {
        Err(Error::new(Code::NotSup))
    }

    fn next_out(&mut self, _stream: &mut GateIStream) -> Result<(), Error> {
        Err(Error::new(Code::NotSup))
    }

    fn commit(&mut self, _stream: &mut GateIStream) -> Result<(), Error> {
        Err(Error::new(Code::NotSup))
    }

    fn seek(&mut self, _stream: &mut GateIStream) -> Result<(), Error> {
        Err(Error::new(Code::NotSup))
    }

    fn fstat(&mut self, _stream: &mut GateIStream) -> Result<(), Error> {
        Err(Error::new(Code::NotSup))
    }

    fn stat(&mut self, stream: &mut GateIStream) -> Result<(), Error> {
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

    fn mkdir(&mut self, stream: &mut GateIStream) -> Result<(), Error> {
        let path: &str = stream.pop()?;
        let mode = FileMode::from_bits_truncate(stream.pop::<u32>()?) & FileMode::PERM;

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

    fn rmdir(&mut self, stream: &mut GateIStream) -> Result<(), Error> {
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

    fn link(&mut self, stream: &mut GateIStream) -> Result<(), Error> {
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

    fn unlink(&mut self, stream: &mut GateIStream) -> Result<(), Error> {
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

    fn rename(&mut self, stream: &mut GateIStream) -> Result<(), Error> {
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
}
