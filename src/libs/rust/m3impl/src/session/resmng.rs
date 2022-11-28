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

use base::serialize::{Deserialize, Serialize};

use crate::build_vmsg;
use crate::cap::Selector;
use crate::cell::StaticRefCell;
use crate::col::String;
use crate::col::ToString;
use crate::com::{GateIStream, RecvGate, SendGate};
use crate::errors::{Code, Error};
use crate::goff;
use crate::int_enum;
use crate::kif;
use crate::mem::MsgBuf;
use crate::quota::Quota;
use crate::tcu::{ActId, TileId};
use crate::tiles::Activity;

// use a separate message buffer here, because the default buffer could be in use for a message over
// a SendGate, for which the reply gate needs to activated first, possibly involving a MemGate
// creation via the resource manager.
static RESMNG_BUF: StaticRefCell<MsgBuf> = StaticRefCell::new(MsgBuf::new_initialized());

int_enum! {
    /// The resource manager calls
    pub struct Operation : u64 {
        const REG_SERV      = 0x0;
        const UNREG_SERV    = 0x1;

        const OPEN_SESS     = 0x2;
        const CLOSE_SESS    = 0x3;

        const ADD_CHILD     = 0x4;
        const REM_CHILD     = 0x5;

        const ALLOC_MEM     = 0x6;
        const FREE_MEM      = 0x7;

        const ALLOC_TILE    = 0x8;
        const FREE_TILE     = 0x9;

        const USE_RGATE     = 0xA;
        const USE_SGATE     = 0xB;

        const USE_SEM       = 0xC;

        const GET_SERIAL    = 0xD;

        const GET_INFO      = 0xE;

        const QUOTE         = 0xF;
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct RegServiceReq {
    pub dst: Selector,
    pub sgate: Selector,
    pub name: String,
    pub sessions: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct FreeReq {
    pub sel: Selector,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct OpenSessionReq {
    pub dst: Selector,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct AllocMemReq {
    pub dst: Selector,
    pub addr: goff,
    pub size: goff,
    pub perms: kif::Perm,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct AllocTileReq {
    pub dst: Selector,
    pub desc: kif::TileDesc,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct AllocTileReply {
    pub id: TileId,
    pub desc: kif::TileDesc,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct UseReq {
    pub dst: Selector,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct UseRGateReply {
    pub order: u32,
    pub msg_order: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct GetSerialReq {
    pub dst: Selector,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct GetInfoReq {
    pub idx: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct AddChildReq {
    pub id: ActId,
    pub sel: Selector,
    pub sgate: Selector,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct QuoteReply {
    pub quote: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct ActInfo {
    pub id: ActId,
    pub layer: u32,
    pub name: String,
    pub daemon: bool,
    pub umem: Quota<usize>,
    pub kmem: Quota<usize>,
    pub eps: Quota<u32>,
    pub time: Quota<u64>,
    pub pts: Quota<usize>,
    pub tile: TileId,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub enum ActInfoResult {
    Info(ActInfo),
    Count((usize, u32)),
}

/// Represents a connection to the resource manager.
///
/// The resource manager is used to request access to resources like memory and services and is
/// provided by any of the parent activities.
pub struct ResMng {
    sgate: SendGate,
    act_sel: Selector,
}

impl ResMng {
    /// Creates a new `ResMng` with given [`SendGate`] to send requests to the server.
    pub fn new(sgate: SendGate) -> Self {
        ResMng {
            sgate,
            act_sel: kif::INVALID_SEL,
        }
    }

    /// Returns the capability selector of the [`SendGate`] used for requests.
    pub fn sel(&self) -> Selector {
        self.sgate.sel()
    }

    /// Clones this connection to be used by the given activity as well. `name` specifies the name of the
    /// activity.
    pub fn clone(&self, act: &mut Activity, sgate: Selector, name: &str) -> Result<Self, Error> {
        Self::send_receive(&self.sgate, Operation::ADD_CHILD, AddChildReq {
            id: act.id(),
            sel: act.sel(),
            sgate,
            name: name.to_string(),
        })
        .map(|_| ResMng {
            sgate: SendGate::new_bind(sgate),
            act_sel: act.sel(),
        })
    }

    /// Registers a service with given name at selector `dst`, using `sgate` for session creations.
    pub fn reg_service(
        &self,
        dst: Selector,
        sgate: Selector,
        name: &str,
        sessions: u32,
    ) -> Result<(), Error> {
        Self::send_receive(&self.sgate, Operation::REG_SERV, RegServiceReq {
            dst,
            sgate,
            sessions,
            name: name.to_string(),
        })
        .map(|_| ())
    }

    /// Unregisters the service with given selector.
    pub fn unreg_service(&self, sel: Selector) -> Result<(), Error> {
        Self::send_receive(&self.sgate, Operation::UNREG_SERV, FreeReq { sel }).map(|_| ())
    }

    /// Opens a session at service `name` using selector `dst`.
    pub fn open_sess(&self, dst: Selector, name: &str) -> Result<(), Error> {
        Self::send_receive(&self.sgate, Operation::OPEN_SESS, OpenSessionReq {
            dst,
            name: name.to_string(),
        })
        .map(|_| ())
    }

    /// Closes the session with given selector.
    pub fn close_sess(&self, sel: Selector) -> Result<(), Error> {
        Self::send_receive(&self.sgate, Operation::CLOSE_SESS, FreeReq { sel }).map(|_| ())
    }

    /// Allocates `size` bytes of physical memory with given permissions. If `addr` is not `!0`, it
    /// will be allocated at that address.
    pub fn alloc_mem(
        &self,
        dst: Selector,
        addr: goff,
        size: goff,
        perms: kif::Perm,
    ) -> Result<(), Error> {
        Self::send_receive(&self.sgate, Operation::ALLOC_MEM, AllocMemReq {
            dst,
            addr,
            size,
            perms,
        })
        .map(|_| ())
    }

    /// Free's the memory with given selector.
    pub fn free_mem(&self, sel: Selector) -> Result<(), Error> {
        Self::send_receive(&self.sgate, Operation::FREE_MEM, FreeReq { sel }).map(|_| ())
    }

    /// Allocates a new processing element of given type and assigns it to selector `dst`.
    pub fn alloc_tile(
        &self,
        dst: Selector,
        desc: kif::TileDesc,
    ) -> Result<(TileId, kif::TileDesc), Error> {
        let mut reply = Self::send_receive(&self.sgate, Operation::ALLOC_TILE, AllocTileReq {
            dst,
            desc,
        })?;
        let reply: AllocTileReply = reply.pop()?;
        Ok((reply.id, reply.desc))
    }

    /// Free's the processing element with given selector
    pub fn free_tile(&self, sel: Selector) -> Result<(), Error> {
        Self::send_receive(&self.sgate, Operation::FREE_TILE, FreeReq { sel }).map(|_| ())
    }

    /// Attaches to the RecvGate with given name using selector `dst`.
    pub fn use_rgate(&self, dst: Selector, name: &str) -> Result<(u32, u32), Error> {
        let mut reply = Self::send_receive(&self.sgate, Operation::USE_RGATE, UseReq {
            dst,
            name: name.to_string(),
        })?;
        let reply: UseRGateReply = reply.pop()?;
        Ok((reply.order, reply.msg_order))
    }

    /// Attaches to the SendGate with given name using selector `dst`.
    pub fn use_sgate(&self, dst: Selector, name: &str) -> Result<(), Error> {
        Self::send_receive(&self.sgate, Operation::USE_SGATE, UseReq {
            dst,
            name: name.to_string(),
        })
        .map(|_| ())
    }

    /// Attaches to the semaphore with given name using selector `dst`.
    pub fn use_sem(&self, dst: Selector, name: &str) -> Result<(), Error> {
        Self::send_receive(&self.sgate, Operation::USE_SEM, UseReq {
            dst,
            name: name.to_string(),
        })
        .map(|_| ())
    }

    /// Retrieves the receive gate to receive serial input
    pub fn get_serial(&self, dst: Selector) -> Result<RecvGate, Error> {
        Self::send_receive(&self.sgate, Operation::GET_SERIAL, GetSerialReq { dst })
            .map(|_| RecvGate::new_bind(dst))
    }

    /// Gets the number of available activities for `get_activity_info` and the starting layer.
    pub fn get_activity_count(&self) -> Result<(usize, u32), Error> {
        match self.activity_info(None) {
            Ok(ActInfoResult::Count((num, layer))) => Ok((num, layer)),
            Err(e) => Err(e),
            _ => panic!("unexpected info type"),
        }
    }

    /// Retrieves information about the activity with given index.
    pub fn get_activity_info(&self, act_idx: usize) -> Result<ActInfo, Error> {
        match self.activity_info(Some(act_idx)) {
            Ok(ActInfoResult::Info(i)) => Ok(i),
            Err(e) => Err(e),
            _ => panic!("unexpected info type"),
        }
    }

    /// Requests a quote for the current subsystem state
    pub fn quote(&self) -> Result<String, Error> {
        let reply: QuoteReply =
            Self::send_receive(&self.sgate, Operation::QUOTE, 0).and_then(|mut is| is.pop())?;
        Ok(reply.quote)
    }

    fn activity_info(&self, act_idx: Option<usize>) -> Result<ActInfoResult, Error> {
        Self::send_receive(&self.sgate, Operation::GET_INFO, GetInfoReq {
            idx: act_idx.unwrap_or(usize::MAX),
        })
        .and_then(|mut is| is.pop())
    }

    fn send_receive<R: Serialize>(
        sgate: &SendGate,
        op: Operation,
        req: R,
    ) -> Result<GateIStream<'_>, Error> {
        let reply_gate = RecvGate::def();

        let mut buf = RESMNG_BUF.borrow_mut();
        build_vmsg!(buf, op, req);

        let mut reply = GateIStream::new(sgate.call(&buf, reply_gate)?, reply_gate);
        let res = Code::from(reply.pop::<u32>()?);
        match res {
            Code::Success => Ok(reply),
            e => Err(Error::new(e)),
        }
    }
}

impl Drop for ResMng {
    fn drop(&mut self) {
        if self.act_sel != kif::INVALID_SEL {
            Self::send_receive(
                &Activity::own().resmng().unwrap().sgate,
                Operation::REM_CHILD,
                FreeReq { sel: self.act_sel },
            )
            .ok();
        }
    }
}
