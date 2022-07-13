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

//! The kernel-tilemux interface

use num_enum::IntoPrimitive;

use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::errors::Code;
use crate::kif::PageFlags;
use crate::mem::{GlobAddr, VirtAddr};
use crate::serialize::{Deserialize, Serialize};
use crate::tcu::{ActId, EpId};

/// The activity id of TileMux
pub const ACT_ID: u64 = 0xFFFF;
/// The activity id when TileMux is idling
pub const IDLE_ID: u64 = 0xFFFE;

pub type QuotaId = u64;

pub const IDLE_QUOTA_ID: QuotaId = 0;
pub const DEF_QUOTA_ID: QuotaId = 1;

/// The sidecalls from the kernel to TileMux
#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive, Serialize_repr, Deserialize_repr)]
#[repr(u64)]
pub enum Sidecalls {
    ActInit,
    ActCtrl,
    Map,
    Translate,
    RemMsgs,
    EPInval,
    DeriveQuota,
    GetQuota,
    SetQuota,
    RemoveQuotas,
    ResetStats,
    Shutdown,
}

/// The operations for the `act_ctrl` sidecall
#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive, Serialize_repr, Deserialize_repr)]
#[repr(u64)]
pub enum ActivityOp {
    Start,
    Stop,
}

/// The activity init sidecall
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct ActInit {
    pub act_id: u64,
    pub bw_quota: QuotaId,
    pub time_quota: QuotaId,
    pub pt_quota: QuotaId,
    pub eps_start: EpId,
}

/// The activity control sidecall
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct ActivityCtrl {
    pub act_id: u64,
    pub act_op: ActivityOp,
}

/// The map sidecall
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct Map {
    pub act_id: u64,
    pub virt: VirtAddr,
    pub global: GlobAddr,
    pub pages: usize,
    pub perm: PageFlags,
}

/// The translate sidecall
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct Translate {
    pub act_id: u64,
    pub virt: VirtAddr,
    pub perm: PageFlags,
}

/// The remove messages sidecall
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct RemMsgs {
    pub act_id: u64,
    pub unread_mask: u32,
}

/// The EP invalidation sidecall
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct EpInval {
    pub act_id: u64,
    pub ep: EpId,
}

/// The derive quota sidecall
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct DeriveQuota {
    pub parent_time: QuotaId,
    pub parent_pts: QuotaId,
    pub time: Option<u64>,
    pub pts: Option<usize>,
}

/// The get quota sidecall
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct GetQuota {
    pub time: QuotaId,
    pub pts: QuotaId,
}

/// The set quota sidecall
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct SetQuota {
    pub id: QuotaId,
    pub time: u64,
    pub pts: usize,
}

/// The remove quotas sidecall
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct RemoveQuotas {
    pub time: Option<QuotaId>,
    pub pts: Option<QuotaId>,
}

/// The reset stats sidecall
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct ResetStats {}

/// The shutdown sidecall
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct Shutdown {}

/// The sidecall response
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct Response {
    pub val1: u64,
    pub val2: u64,
}

/// The calls from TileMux to the kernel
#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive, Serialize_repr, Deserialize_repr)]
#[repr(u64)]
pub enum Calls {
    Exit,
}

/// The exit call
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct Exit {
    pub act_id: ActId,
    pub status: Code,
}
