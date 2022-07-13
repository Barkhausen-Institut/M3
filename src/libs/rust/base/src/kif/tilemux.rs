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

use crate::goff;
use crate::kif::PageFlags;
use crate::mem::GlobAddr;
use crate::serialize::{Deserialize, Serialize};
use crate::tcu::{ActId, EpId};

/// The activity id of TileMux
pub const ACT_ID: u64 = 0xFFFF;
/// The activity id when TileMux is idling
pub const IDLE_ID: u64 = 0xFFFE;

pub type QuotaId = u64;

pub const IDLE_QUOTA_ID: QuotaId = 0;
pub const DEF_QUOTA_ID: QuotaId = 1;

int_enum! {
    /// The sidecalls from the kernel to TileMux
    pub struct Sidecalls : u64 {
        const ACT_INIT       = 0x0;
        const ACT_CTRL       = 0x1;
        const MAP            = 0x2;
        const TRANSLATE      = 0x3;
        const REM_MSGS       = 0x4;
        const EP_INVAL       = 0x5;
        const DERIVE_QUOTA   = 0x6;
        const GET_QUOTA      = 0x7;
        const SET_QUOTA      = 0x8;
        const REMOVE_QUOTAS  = 0x9;
        const RESET_STATS    = 0xA;
        const SHUTDOWN       = 0xB;
    }
}

int_enum! {
    /// The operations for the `act_ctrl` sidecall
    pub struct ActivityOp : u64 {
        const START = 0x0;
        const STOP  = 0x1;
    }
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
    pub virt: goff,
    pub global: GlobAddr,
    pub pages: usize,
    pub perm: PageFlags,
}

/// The translate sidecall
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct Translate {
    pub act_id: u64,
    pub virt: goff,
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

int_enum! {
    /// The calls from TileMux to the kernel
    pub struct Calls : u64 {
        const EXIT           = 0x0;
    }
}

/// The exit call
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct Exit {
    pub act_id: ActId,
    pub status: i32,
}
