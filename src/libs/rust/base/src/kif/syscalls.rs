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

//! The system call interface

use num_enum::{IntoPrimitive, TryFromPrimitive};

use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::errors::Code;
use crate::kif::{tilemux::QuotaId, CapRngDesc, CapSel, Perm};
use crate::mem::{GlobAddr, GlobOff, VirtAddr};
use crate::serialize::{Deserialize, Serialize};
use crate::tcu::{ActId, EpId, Label};

/// The maximum number of arguments for the exchange syscalls
pub const MAX_EXCHG_ARGS: usize = 8;

/// The maximum number of activities one can wait for
pub const MAX_WAIT_ACTS: usize = 32;

/// The system calls
#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive, TryFromPrimitive, Serialize_repr)]
#[repr(u64)]
pub enum Operation {
    // Capability creations
    CreateSrv,
    CreateSess,
    CreateMGate,
    CreateRGate,
    CreateSGate,
    CreateMap,
    CreateAct,
    CreateSem,
    AllocEP,

    // Capability operations
    Activate,
    ActCtrl,
    ActWait,
    DeriveMem,
    DeriveKMem,
    DeriveTile,
    DeriveSrv,
    GetSess,
    MGateRegion,
    RGateBuffer,
    KMemQuota,
    TileQuota,
    TileSetQuota,
    TileSetPMP,
    TileMem,
    TileReset,
    SemCtrl,

    // Capability exchange
    ExchangeSess,
    Exchange,
    Revoke,

    // Misc
    ResetStats,
    Noop,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct CreateSrv<'s> {
    pub dst: CapSel,
    pub rgate: CapSel,
    pub creator: usize,
    pub name: &'s str,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct CreateSess {
    pub dst: CapSel,
    pub srv: CapSel,
    pub creator: usize,
    pub ident: u64,
    pub auto_close: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct CreateMGate {
    pub dst: CapSel,
    pub act: CapSel,
    pub addr: VirtAddr,
    pub size: GlobOff,
    pub perms: Perm,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct CreateRGate {
    pub dst: CapSel,
    pub order: u32,
    pub msg_order: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct CreateSGate {
    pub dst: CapSel,
    pub rgate: CapSel,
    pub label: Label,
    pub credits: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct CreateMap {
    pub dst: CapSel,
    pub act: CapSel,
    pub mgate: CapSel,
    pub first: CapSel,
    pub pages: CapSel,
    pub perms: Perm,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct CreateActivity<'s> {
    pub dst: CapSel,
    pub tile: CapSel,
    pub kmem: CapSel,
    pub name: &'s str,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct CreateSem {
    pub dst: CapSel,
    pub value: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct AllocEP {
    pub dst: CapSel,
    pub act: CapSel,
    pub epid: EpId,
    pub replies: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct Activate {
    pub ep: CapSel,
    pub gate: CapSel,
    pub rbuf_mem: CapSel,
    pub rbuf_off: GlobOff,
}

/// The operations for the `act_ctrl` system call
#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive, Serialize_repr, Deserialize_repr)]
#[repr(u64)]
pub enum ActivityOp {
    Start = 1,
    Stop,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct ActivityCtrl {
    pub act: CapSel,
    pub op: ActivityOp,
    pub arg: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct ActivityWait {
    pub event: u64,
    pub act_count: usize,
    pub acts: [CapSel; MAX_WAIT_ACTS],
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct DeriveMem {
    pub act: CapSel,
    pub dst: CapSel,
    pub src: CapSel,
    pub offset: GlobOff,
    pub size: GlobOff,
    pub perms: Perm,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct DeriveKMem {
    pub kmem: CapSel,
    pub dst: CapSel,
    pub quota: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct DeriveTile {
    pub tile: CapSel,
    pub dst: CapSel,
    pub eps: Option<u32>,
    pub bw: Option<u32>,
    pub time: Option<u64>,
    pub pts: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct DeriveSrv {
    pub srv: CapSel,
    pub dst: CapRngDesc,
    pub sessions: u32,
    pub event: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct GetSess {
    pub srv: CapSel,
    pub act: CapSel,
    pub dst: CapSel,
    pub sid: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct MGateRegion {
    pub mgate: CapSel,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct RGateBuffer {
    pub rgate: CapSel,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct KMemQuota {
    pub kmem: CapSel,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct TileQuota {
    pub tile: CapSel,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct TileSetQuota {
    pub tile: CapSel,
    pub bw: u32,
    pub time: u64,
    pub pts: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct TileSetPMP {
    pub tile: CapSel,
    pub mgate: CapSel,
    pub ep: EpId,
    pub overwrite: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct TileMem {
    pub tile: CapSel,
    pub dst: CapSel,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct TileReset {
    pub tile: CapSel,
    pub mux_mem: CapSel,
}

/// The operations for the `sem_ctrl` system call
#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive, Serialize_repr, Deserialize_repr)]
#[repr(u64)]
pub enum SemOp {
    Up,
    Down,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct SemCtrl {
    pub sem: CapSel,
    pub op: SemOp,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExchangeArgs {
    pub bytes: usize,
    pub data: [u64; 8],
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct ExchangeSess {
    pub act: CapSel,
    pub sess: CapSel,
    pub crd: CapRngDesc,
    pub args: ExchangeArgs,
    pub obtain: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct Exchange {
    pub act: CapSel,
    pub own: CapRngDesc,
    pub other: CapSel,
    pub obtain: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct Revoke {
    pub act: CapSel,
    pub crd: CapRngDesc,
    pub own: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct ResetStats {}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct Noop {}

/// The create activity reply message
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct CreateActivityReply {
    pub id: ActId,
    pub eps_start: EpId,
}

/// The alloc endpoints reply message
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct AllocEPReply {
    pub ep: EpId,
}

/// The activity wait reply message
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct ActivityWaitReply {
    pub act_sel: CapSel,
    pub exitcode: Code,
}

/// The kernel gate region reply message
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct MGateRegionReply {
    pub global: GlobAddr,
    pub size: GlobOff,
}

/// The kernel receive gate buffer reply message
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct RGateBufferReply {
    pub order: u32,
    pub msg_order: u32,
}

/// The kernel memory quota reply message
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct KMemQuotaReply {
    pub id: QuotaId,
    pub total: usize,
    pub left: usize,
}

/// The tile quota reply message
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct TileQuotaReply {
    pub eps_id: QuotaId,
    pub eps_total: u32,
    pub eps_left: u32,
    pub bw_id: QuotaId,
    pub bw_total: u32,
    pub bw_left: u32,
    pub time_id: QuotaId,
    pub time_total: u64,
    pub time_left: u64,
    pub pts_id: QuotaId,
    pub pts_total: usize,
    pub pts_left: usize,
}

/// The delegate/obtain reply message
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct ExchangeSessReply {
    pub args: ExchangeArgs,
}
