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

use crate::boxed::Box;
use crate::cap::Selector;
use crate::com::{MemGate, RecvGate, SendGate};
use crate::errors::Error;
use crate::int_enum;
use crate::kif::{CapRngDesc, CapType};
use crate::session::ClientSession;
use crate::vfs::{File, GenFileOp, GenericFile, OpenFlags};

/// Represents a session at the pipes server.
pub struct Pipes {
    sess: ClientSession,
}

int_enum! {
    /// The pipe operations.
    pub struct PipeOperation : u64 {
        const OPEN_PIPE     = GenFileOp::REQ_NOTIFY.val + 1;
        const OPEN_CHAN     = Self::OPEN_PIPE.val + 1;
        const SET_MEM       = Self::OPEN_CHAN.val + 1;
        const CLOSE_PIPE    = Self::SET_MEM.val + 1;
    }
}

impl Pipes {
    /// Creates a new `Pipes` session at service with given name.
    pub fn new(name: &str) -> Result<Self, Error> {
        let sess = ClientSession::new(name)?;
        Ok(Pipes { sess })
    }

    /// Creates a new pipe using `mem` of `mem_size` bytes as shared memory for the data exchange.
    pub fn create_pipe(&self, mem: &MemGate, mem_size: usize) -> Result<Pipe, Error> {
        let crd = self.sess.obtain(
            2,
            |os| {
                os.push_word(PipeOperation::OPEN_PIPE.val);
                os.push_word(mem_size as u64);
            },
            |_| Ok(()),
        )?;
        Pipe::new(mem, crd.start())
    }
}

/// Represents a pipe.
pub struct Pipe {
    sess: ClientSession,
    sgate: SendGate,
}

impl Pipe {
    fn new(mem: &MemGate, sel: Selector) -> Result<Self, Error> {
        let sess = ClientSession::new_bind(sel);
        sess.delegate(
            CapRngDesc::new(CapType::OBJECT, mem.sel(), 1),
            |os| {
                os.push_word(PipeOperation::SET_MEM.val);
            },
            |_| Ok(()),
        )?;
        Ok(Pipe {
            sess,
            sgate: SendGate::new_bind(sel + 1),
        })
    }

    /// Returns the session's capability selector.
    pub fn sel(&self) -> Selector {
        self.sess.sel()
    }

    /// Creates a new channel for this pipe. If `read` is true, it is a read-end, otherwise a
    /// write-end.
    pub fn create_chan(&self, read: bool) -> Result<Box<dyn File>, Error> {
        let crd = self.sess.obtain(
            2,
            |os| {
                os.push_word(PipeOperation::OPEN_CHAN.val);
                os.push_word(read as u64);
            },
            |_| Ok(()),
        )?;
        let flags = if read {
            OpenFlags::R | OpenFlags::NEW_SESS
        }
        else {
            OpenFlags::W | OpenFlags::NEW_SESS
        };
        Ok(Box::new(GenericFile::new(flags, crd.start(), None)))
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        send_recv_res!(&self.sgate, RecvGate::def(), PipeOperation::CLOSE_PIPE).unwrap();
    }
}
