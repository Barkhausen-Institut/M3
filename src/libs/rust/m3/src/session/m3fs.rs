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
use core::fmt;

use crate::boxed::Box;
use crate::cap::Selector;
use crate::cell::RefCell;
use crate::col::Vec;
use crate::com::{recv_result, RecvGate, SendGate, EP};
use crate::errors::Error;
use crate::goff;
use crate::kif;
use crate::rc::Rc;
use crate::serialize::Source;
use crate::session::ClientSession;
use crate::tiles::{Activity, ChildActivity, StateSerializer};
use crate::vfs::{
    FSHandle, FSOperation, File, FileInfo, FileMode, FileSystem, GenericFile, OpenFlags,
    StatResponse,
};

struct CachedEP {
    id: usize,
    ep: EP,
    file: Option<usize>,
}

/// Represents a session at m3fs.
pub struct M3FS {
    id: usize,
    sess: ClientSession,
    sgate: Rc<SendGate>,
    eps: Vec<CachedEP>,
}

impl M3FS {
    fn create(id: usize, sess: ClientSession, sgate: SendGate) -> FSHandle {
        Rc::new(RefCell::new(M3FS {
            id,
            sess,
            sgate: Rc::new(sgate),
            eps: Vec::new(),
        }))
    }

    /// Creates a new session at the m3fs server with given name.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(id: usize, name: &str) -> Result<FSHandle, Error> {
        let sels = Activity::own().alloc_sels(2);
        let sess = ClientSession::new_with_sel(name, sels + 0)?;

        let crd = kif::CapRngDesc::new(kif::CapType::OBJECT, sels + 1, 1);
        sess.obtain_for(
            Activity::own().sel(),
            crd,
            |os| os.push_word(FSOperation::GET_SGATE.val),
            |_| Ok(()),
        )?;
        let sgate = SendGate::new_bind(sels + 1);
        Ok(Self::create(id, sess, sgate))
    }

    /// Binds a new m3fs-session to selectors `sels`..`sels+1`.
    pub fn new_bind(id: usize, sels: Selector) -> FSHandle {
        Self::create(
            id,
            ClientSession::new_bind(sels + 0),
            SendGate::new_bind(sels + 1),
        )
    }

    /// Returns a reference to the underlying [`ClientSession`]
    pub fn sess(&self) -> &ClientSession {
        &self.sess
    }

    pub fn get_mem(sess: &ClientSession, off: goff) -> Result<(goff, goff, Selector), Error> {
        let mut offset = 0;
        let mut len = 0;
        let crd = sess.obtain(
            1,
            |os| {
                os.push_word(FSOperation::GET_MEM.val);
                os.push_word(off as u64);
            },
            |is| {
                offset = is.pop_word()?;
                len = is.pop_word()?;
                Ok(())
            },
        )?;
        Ok((offset, len, crd.start()))
    }
}

impl FileSystem for M3FS {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn id(&self) -> usize {
        self.id
    }

    fn open(&mut self, path: &str, flags: OpenFlags) -> Result<Box<dyn File>, Error> {
        if !flags.contains(OpenFlags::NEW_SESS) {
            let ep_idx = self.get_ep()?;

            let mut reply = send_recv_res!(
                &self.sgate,
                RecvGate::def(),
                FSOperation::OPEN_PRIV,
                path,
                u64::from(flags.bits()),
                self.eps[ep_idx].id
            )?;
            let file_id: usize = reply.pop()?;

            // mark ep as in-use
            self.eps[ep_idx].file = Some(file_id);

            Ok(Box::new(GenericFile::new_without_sess(
                flags,
                self.sess.sel(),
                file_id,
                self.id(),
                self.eps[ep_idx].ep.id(),
                self.sgate.clone(),
            )))
        }
        else {
            let crd = self.sess.obtain(
                2,
                |os| {
                    os.push_word(FSOperation::OPEN.val);
                    os.push_word(u64::from(flags.bits()));
                    os.push_str(path);
                },
                |_| Ok(()),
            )?;
            Ok(Box::new(GenericFile::new(
                flags,
                crd.start(),
                Some(self.id()),
            )))
        }
    }

    fn close(&mut self, file_id: usize) {
        for ep in &mut self.eps {
            if matches!(ep.file, Some(fid) if fid == file_id) {
                ep.file = None;
                break;
            }
        }
    }

    fn stat(&self, path: &str) -> Result<FileInfo, Error> {
        send_vmsg!(&self.sgate, RecvGate::def(), FSOperation::STAT, path)?;
        let reply = recv_result(RecvGate::def(), Some(&self.sgate))?;
        let resp = reply.msg().get_data::<StatResponse>();
        FileInfo::from_response(resp)
    }

    fn mkdir(&self, path: &str, mode: FileMode) -> Result<(), Error> {
        send_recv_res!(
            &self.sgate,
            RecvGate::def(),
            FSOperation::MKDIR,
            path,
            mode.bits()
        )
        .map(|_| ())
    }

    fn rmdir(&self, path: &str) -> Result<(), Error> {
        send_recv_res!(&self.sgate, RecvGate::def(), FSOperation::RMDIR, path).map(|_| ())
    }

    fn link(&self, old_path: &str, new_path: &str) -> Result<(), Error> {
        send_recv_res!(
            &self.sgate,
            RecvGate::def(),
            FSOperation::LINK,
            old_path,
            new_path
        )
        .map(|_| ())
    }

    fn unlink(&self, path: &str) -> Result<(), Error> {
        send_recv_res!(&self.sgate, RecvGate::def(), FSOperation::UNLINK, path).map(|_| ())
    }

    fn rename(&self, old_path: &str, new_path: &str) -> Result<(), Error> {
        send_recv_res!(
            &self.sgate,
            RecvGate::def(),
            FSOperation::RENAME,
            old_path,
            new_path
        )
        .map(|_| ())
    }

    fn fs_type(&self) -> u8 {
        b'M'
    }

    fn delegate(&self, act: &ChildActivity) -> Result<Selector, Error> {
        act.delegate_obj(self.sess.sel())?;

        let crd = kif::CapRngDesc::new(kif::CapType::OBJECT, self.sess.sel() + 1, 1);
        self.sess.obtain_for(
            act.sel(),
            crd,
            |os| os.push_word(FSOperation::GET_SGATE.val),
            |_| Ok(()),
        )?;

        Ok(self.sess.sel() + 2)
    }

    fn serialize(&self, s: &mut StateSerializer<'_>) {
        s.push_word(self.sess.sel() as u64);
        s.push_word(self.id() as u64);
    }
}

impl M3FS {
    fn get_ep(&mut self) -> Result<usize, Error> {
        for (i, ep) in self.eps.iter_mut().enumerate() {
            if ep.file.is_none() {
                return Ok(i);
            }
        }

        let ep = Activity::own().epmng_mut().acquire(0)?;
        let id = self.delegate_ep(ep.sel())?;
        self.eps.push(CachedEP { id, ep, file: None });
        Ok(self.eps.len() - 1)
    }

    fn delegate_ep(&self, sel: Selector) -> Result<usize, Error> {
        let mut id = 0;
        self.sess.delegate(
            kif::CapRngDesc::new(kif::CapType::OBJECT, sel, 1),
            |os| os.push_word(FSOperation::DEL_EP.val),
            |is| {
                id = is.pop_word()? as usize;
                Ok(())
            },
        )?;
        Ok(id)
    }

    pub fn unserialize(s: &mut Source<'_>) -> FSHandle {
        let sels: Selector = s.pop().unwrap();
        let id: usize = s.pop().unwrap();
        M3FS::new_bind(id, sels)
    }
}

impl fmt::Debug for M3FS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "M3FS[id={}, sess={:?}, sgate={:?}]",
            self.id, self.sess, self.sgate
        )
    }
}
