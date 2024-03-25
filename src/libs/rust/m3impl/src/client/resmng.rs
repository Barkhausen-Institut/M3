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
use crate::com::{opcodes, GateIStream, RecvGate, SendCap, SendGate};
use crate::errors::{Code, Error};
use crate::kif;
use crate::mem::{GlobOff, MsgBuf};
use crate::quota::Quota;
use crate::tcu::{ActId, TileId};
use crate::tiles::Activity;
use crate::time::TimeDuration;

// use a separate message buffer here, because the default buffer could be in use for a message over
// a SendGate, for which the reply gate needs to activated first, possibly involving a MemGate
// creation via the resource manager.
static RESMNG_BUF: StaticRefCell<MsgBuf> = StaticRefCell::new(MsgBuf::new_initialized());

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
    pub size: GlobOff,
    pub perms: kif::Perm,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct AllocTileReq {
    pub dst: Selector,
    pub desc: kif::TileDesc,
    pub init: bool,
    pub inherit_pmp: bool,
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
    pub act: Selector,
    pub tile: Selector,
    pub kmem: Selector,
    pub sgate: Selector,
    pub name: String,
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
    pub eps: Quota<usize>,
    pub time: Quota<TimeDuration>,
    pub pts: Quota<usize>,
    pub tile: TileId,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub enum ActInfoResult {
    Info(ActInfo),
    Count((usize, u32)),
}

/// Represents a connection to the resource manager
///
/// The resource manager is a special service that every application is implicitly connected to,
/// because every application is (directly or indirectly) started by a resource manager. The
/// resource manager will therefore create a connection for each application before starting it.
///
/// As the name implies, resource managers are responsible to manage a certain set of resources and
/// distribute them among their clients. Examples are tiles, memory, CPU time, and services. To
/// obtain access to such resources, clients need to send a request to their resource manager.
/// Depending on what has been defined for the client and depending on the availability, the
/// resource manager will grant access or not.
///
/// The access permissions and resource shares of each applications and services are defined via a
/// *configuration file* or *boot script* in form of XML. The XML file specifies what applications
/// and services should be started including their permissions and resource shares. See the `boot`
/// directory for examples.
pub struct ResMng {
    sgate: SendGate,
}

impl ResMng {
    /// Creates a new `ResMng` with given [`SendGate`] to send requests to the server.
    pub fn new(sgate: SendGate) -> Self {
        ResMng { sgate }
    }

    /// Returns the capability selector of the [`SendGate`] used for requests.
    pub fn sel(&self) -> Selector {
        self.sgate.sel()
    }

    /// Clones this connection to be used by the given activity as well. `name` specifies the name of the
    /// activity.
    pub fn clone(
        &self,
        act: &mut Activity,
        sgate: Selector,
        name: &str,
    ) -> Result<ResMngChild, Error> {
        Self::send_receive(&self.sgate, opcodes::ResMng::AddChild, AddChildReq {
            id: act.id(),
            act: act.sel(),
            tile: act.tile().sel(),
            kmem: act.kmem().sel(),
            sgate,
            name: name.to_string(),
        })
        .map(|_| ResMngChild::new_clone(SendCap::new_bind(sgate), act.sel()))
    }

    /// Registers a service with given name at selector `dst`, using `sgate` for session creations.
    pub fn reg_service(
        &self,
        dst: Selector,
        sgate: Selector,
        name: &str,
        sessions: u32,
    ) -> Result<(), Error> {
        Self::send_receive(&self.sgate, opcodes::ResMng::RegServ, RegServiceReq {
            dst,
            sgate,
            sessions,
            name: name.to_string(),
        })
        .map(|_| ())
    }

    /// Unregisters the service with given selector.
    pub fn unreg_service(&self, sel: Selector) -> Result<(), Error> {
        Self::send_receive(&self.sgate, opcodes::ResMng::UnregServ, FreeReq { sel }).map(|_| ())
    }

    /// Opens a session at service `name` using selector `dst`.
    pub fn open_sess(&self, dst: Selector, name: &str) -> Result<(), Error> {
        Self::send_receive(&self.sgate, opcodes::ResMng::OpenSess, OpenSessionReq {
            dst,
            name: name.to_string(),
        })
        .map(|_| ())
    }

    /// Closes the session with given selector.
    pub fn close_sess(&self, sel: Selector) -> Result<(), Error> {
        Self::send_receive(&self.sgate, opcodes::ResMng::CloseSess, FreeReq { sel }).map(|_| ())
    }

    /// Allocates `size` bytes of physical memory with given permissions.
    pub fn alloc_mem(&self, dst: Selector, size: GlobOff, perms: kif::Perm) -> Result<(), Error> {
        Self::send_receive(&self.sgate, opcodes::ResMng::AllocMem, AllocMemReq {
            dst,
            size,
            perms,
        })
        .map(|_| ())
    }

    /// Free's the memory with given selector.
    pub fn free_mem(&self, sel: Selector) -> Result<(), Error> {
        Self::send_receive(&self.sgate, opcodes::ResMng::FreeMem, FreeReq { sel }).map(|_| ())
    }

    /// Allocates a new processing element of given type and assigns it to selector `dst`.
    ///
    /// If `init` is set, the tile is initialized with the corresponding multiplexer (depends on
    /// the tile type). If `inherit_pmp` is set, all PMP EPs for the this tile are inherited to the
    /// allocated tile.
    pub fn alloc_tile(
        &self,
        dst: Selector,
        desc: kif::TileDesc,
        init: bool,
        inherit_pmp: bool,
    ) -> Result<(TileId, kif::TileDesc), Error> {
        let mut reply =
            Self::send_receive(&self.sgate, opcodes::ResMng::AllocTile, AllocTileReq {
                dst,
                desc,
                init,
                inherit_pmp,
            })?;
        let reply: AllocTileReply = reply.pop()?;
        Ok((reply.id, reply.desc))
    }

    /// Free's the processing element with given selector
    pub fn free_tile(&self, sel: Selector) -> Result<(), Error> {
        Self::send_receive(&self.sgate, opcodes::ResMng::FreeTile, FreeReq { sel }).map(|_| ())
    }

    /// Attaches to the RecvGate with given name using selector `dst`.
    pub fn use_rgate(&self, dst: Selector, name: &str) -> Result<(u32, u32), Error> {
        let mut reply = Self::send_receive(&self.sgate, opcodes::ResMng::UseRGate, UseReq {
            dst,
            name: name.to_string(),
        })?;
        let reply: UseRGateReply = reply.pop()?;
        Ok((reply.order, reply.msg_order))
    }

    /// Attaches to the SendGate with given name using selector `dst`.
    pub fn use_sgate(&self, dst: Selector, name: &str) -> Result<(), Error> {
        Self::send_receive(&self.sgate, opcodes::ResMng::UseSGate, UseReq {
            dst,
            name: name.to_string(),
        })
        .map(|_| ())
    }

    /// Attaches to the semaphore with given name using selector `dst`.
    pub fn use_sem(&self, dst: Selector, name: &str) -> Result<(), Error> {
        Self::send_receive(&self.sgate, opcodes::ResMng::UseSem, UseReq {
            dst,
            name: name.to_string(),
        })
        .map(|_| ())
    }

    /// Attaches to the boot module with given name using selector `dst`.
    pub fn use_mod(&self, dst: Selector, name: &str) -> Result<(), Error> {
        Self::send_receive(&self.sgate, opcodes::ResMng::UseMod, UseReq {
            dst,
            name: name.to_string(),
        })
        .map(|_| ())
    }

    /// Retrieves the receive gate to receive serial input
    pub fn get_serial(&self, dst: Selector) -> Result<RecvGate, Error> {
        Self::send_receive(&self.sgate, opcodes::ResMng::GetSerial, GetSerialReq {
            dst,
        })
        .and_then(|is| {
            drop(is);
            RecvGate::new_bind(dst)
        })
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

    fn activity_info(&self, act_idx: Option<usize>) -> Result<ActInfoResult, Error> {
        Self::send_receive(&self.sgate, opcodes::ResMng::GetInfo, GetInfoReq {
            idx: act_idx.unwrap_or(usize::MAX),
        })
        .and_then(|mut is| is.pop())
    }

    fn send_receive<R: Serialize>(
        sgate: &SendGate,
        op: opcodes::ResMng,
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

/// The resource manager for child activities
pub struct ResMngChild {
    scap: SendCap,
    act_sel: Selector,
}

impl Default for ResMngChild {
    fn default() -> Self {
        Self {
            scap: SendCap::new_bind(kif::INVALID_SEL),
            act_sel: kif::INVALID_SEL,
        }
    }
}

impl ResMngChild {
    fn new_clone(scap: SendCap, act_sel: Selector) -> Self {
        Self { scap, act_sel }
    }

    /// Creates a new instance with given `SendCap` for a self-managed child
    pub fn new(scap: SendCap) -> Self {
        Self {
            scap,
            act_sel: kif::INVALID_SEL,
        }
    }

    /// Returns the selector for the `SendCap` to communicate with the resource manager
    pub fn sel(&self) -> Selector {
        self.scap.sel()
    }
}

impl Drop for ResMngChild {
    fn drop(&mut self) {
        if self.act_sel != kif::INVALID_SEL {
            ResMng::send_receive(
                &Activity::own().resmng().unwrap().sgate,
                opcodes::ResMng::RemChild,
                FreeReq { sel: self.act_sel },
            )
            .ok();
        }
    }
}
