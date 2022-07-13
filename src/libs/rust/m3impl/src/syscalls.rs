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

//! Contains the system call wrapper functions

use base::kif::{self, syscalls, CapRngDesc, Perm, INVALID_SEL};

use core::mem::MaybeUninit;

use crate::build_vmsg;
use crate::cap::Selector;
use crate::cell::{LazyStaticRefCell, Ref, StaticRefCell};
use crate::com::{RecvGate, SendGate};
use crate::errors::{Code, Error};
use crate::goff;
use crate::mem::{GlobAddr, MsgBuf};
use crate::quota::Quota;
use crate::serialize::{Deserialize, M3Deserializer, M3Serializer, SliceSink};
use crate::tcu::{ActId, EpId, Label, Message, SYSC_SEP_OFF};
use crate::tiles::TileQuota;

static SGATE: LazyStaticRefCell<SendGate> = LazyStaticRefCell::default();
// use a separate message buffer here, because the default buffer could be in use for a message over
// a SendGate, which might have to be activated first using a syscall.
static SYSC_BUF: StaticRefCell<MsgBuf> = StaticRefCell::new(MsgBuf::new_initialized());

struct Reply<R> {
    msg: &'static Message,
    data: R,
}

impl<R> Drop for Reply<R> {
    fn drop(&mut self) {
        RecvGate::syscall().ack_msg(self.msg).ok();
    }
}

#[inline(always)]
fn send_receive<'de, R: Deserialize<'de>>(buf: &MsgBuf) -> Result<Reply<R>, Error> {
    let reply_raw = SGATE.borrow().call(buf, RecvGate::syscall())?;

    let mut de = M3Deserializer::new(reply_raw.as_words());
    let res: Code = de.pop()?;
    if res != Code::None {
        RecvGate::syscall().ack_msg(reply_raw)?;
        return Err(Error::new(res));
    }

    Ok(Reply {
        msg: reply_raw,
        data: de.pop()?,
    })
}

#[inline(always)]
fn send_receive_result(buf: &MsgBuf) -> Result<(), Error> {
    #[derive(Deserialize)]
    #[serde(crate = "base::serde")]
    struct Empty {}
    send_receive::<Empty>(buf).map(|_| ())
}

#[doc(hidden)]
pub fn send_gate() -> Ref<'static, SendGate> {
    SGATE.borrow()
}

/// Creates a new service named `name` at selector `dst`. The receive gate `rgate` will be used for
/// service calls from the kernel to the server.
pub fn create_srv(dst: Selector, rgate: Selector, name: &str, creator: usize) -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(buf, syscalls::Operation::CREATE_SRV, syscalls::CreateSrv {
        dst,
        rgate,
        name,
        creator
    });
    send_receive_result(&buf)
}

/// Creates a new memory gate at selector `dst` that refers to the address region
/// `addr`..`addr`+`size` in the address space of `act`. The `addr` and `size` needs to be page
/// aligned.
pub fn create_mgate(
    dst: Selector,
    act: Selector,
    addr: goff,
    size: goff,
    perms: Perm,
) -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(
        buf,
        syscalls::Operation::CREATE_MGATE,
        syscalls::CreateMGate {
            dst,
            act,
            addr,
            size,
            perms,
        }
    );
    send_receive_result(&buf)
}

/// Creates a new send gate at selector `dst` for receive gate `rgate` using the given label and
/// credit amount.
pub fn create_sgate(
    dst: Selector,
    rgate: Selector,
    label: Label,
    credits: u32,
) -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(
        buf,
        syscalls::Operation::CREATE_SGATE,
        syscalls::CreateSGate {
            dst,
            rgate,
            label,
            credits,
        }
    );
    send_receive_result(&buf)
}

/// Creates a new receive gate at selector `dst` with a `2^order` bytes receive buffer and
/// `2^msg_order` bytes message slots.
pub fn create_rgate(dst: Selector, order: u32, msg_order: u32) -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(
        buf,
        syscalls::Operation::CREATE_RGATE,
        syscalls::CreateRGate {
            dst,
            order,
            msg_order,
        }
    );
    send_receive_result(&buf)
}

/// Creates a new session at selector `dst` for service `srv` and given identifier. `auto_close`
/// specifies whether the CLOSE message should be sent to the server as soon as all derived session
/// capabilities have been revoked.
pub fn create_sess(
    dst: Selector,
    srv: Selector,
    creator: usize,
    ident: u64,
    auto_close: bool,
) -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(
        buf,
        syscalls::Operation::CREATE_SESS,
        syscalls::CreateSess {
            dst,
            srv,
            creator,
            ident,
            auto_close,
        }
    );
    send_receive_result(&buf)
}

/// Creates a new mapping at page `dst` for the given activity. The syscall maps `pages` pages to the
/// physical memory given by `mgate`, starting at the page `first` within the physical memory using
/// the given permissions.
///
/// Note that the address and size of `mgate` needs to be page aligned.
///
/// # Examples
///
/// The following example allocates 2 pages of physical memory and maps it to page 10 (virtual
/// address 0xA000).
///
/// ```
/// let mem = MemGate::new(0x2000, MemGate::RW).expect("Unable to alloc mem");
/// syscalls::create_map(10, Activity::own().sel(), mem.sel(), 0, 2, MemGate::RW);
/// ```
pub fn create_map(
    dst: Selector,
    act: Selector,
    mgate: Selector,
    first: Selector,
    pages: Selector,
    perms: Perm,
) -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(buf, syscalls::Operation::CREATE_MAP, syscalls::CreateMap {
        dst,
        act,
        mgate,
        first,
        pages,
        perms,
    });
    send_receive_result(&buf)
}

/// Creates a new activity on tile `tile` with given name at the selector range `dst`.
///
/// The argument `kmem` defines the kernel memory to assign to the activity.
///
/// On success, the function returns the activity id (for debugging purposes) and EP id of the first
/// standard EP.
#[allow(clippy::too_many_arguments)]
pub fn create_activity(
    dst: Selector,
    name: &str,
    tile: Selector,
    kmem: Selector,
) -> Result<(ActId, EpId), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(
        buf,
        syscalls::Operation::CREATE_ACT,
        syscalls::CreateActivity {
            dst,
            name,
            tile,
            kmem
        }
    );

    let reply: Reply<syscalls::CreateActivityReply> = send_receive(&buf)?;
    Ok((reply.data.id, reply.data.eps_start))
}

/// Creates a new semaphore at selector `dst` using `value` as the initial value.
pub fn create_sem(dst: Selector, value: u32) -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(buf, syscalls::Operation::CREATE_SEM, syscalls::CreateSem {
        dst,
        value
    });
    send_receive_result(&buf)
}

/// Allocates a new endpoint for the given activity at selector `dst`. Optionally, it can have `replies`
/// reply slots attached to it (for receive gate activations).
pub fn alloc_ep(dst: Selector, act: Selector, epid: EpId, replies: u32) -> Result<EpId, Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(buf, syscalls::Operation::ALLOC_EP, syscalls::AllocEP {
        dst,
        act,
        epid,
        replies,
    });

    let reply: Reply<syscalls::AllocEPReply> = send_receive(&buf)?;
    Ok(reply.data.ep)
}

/// Sets the given physical-memory-protection EP to the memory region as defined by the `MemGate`
/// on the given tile.
///
/// The EP has to be between 1 and `crate::tcu::PMEM_PROT_EPS` - 1 and will be overwritten with the
/// new memory region. This call requires a non-derived tile capability.
pub fn set_pmp(tile: Selector, mgate: Selector, ep: EpId) -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(buf, syscalls::Operation::SET_PMP, syscalls::SetPMP {
        tile,
        mgate,
        ep
    });
    send_receive_result(&buf)
}

/// Derives a new memory gate for given activity at selector `dst` based on memory gate `sel`.
///
/// The subset of the region is given by `offset` and `size`, whereas the subset of the permissions
/// are given by `perm`.
pub fn derive_mem(
    act: Selector,
    dst: Selector,
    src: Selector,
    offset: goff,
    size: goff,
    perms: Perm,
) -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(buf, syscalls::Operation::DERIVE_MEM, syscalls::DeriveMem {
        act,
        dst,
        src,
        offset,
        size,
        perms,
    });
    send_receive_result(&buf)
}

/// Derives a new kernel memory object at `dst` from `kmem`, transferring `quota` bytes to the new
/// kernel memory object.
pub fn derive_kmem(kmem: Selector, dst: Selector, quota: usize) -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(
        buf,
        syscalls::Operation::DERIVE_KMEM,
        syscalls::DeriveKMem { kmem, dst, quota }
    );
    send_receive_result(&buf)
}

/// Derives a new tile object at `dst` from `tile`, transferring a subset of the resources to the
/// new tile object.
///
/// If a value is not `None`, the corresponding amount is substracted from the current quota (and
/// therefore, needs to be available). If a value is `None`, the quota will be shared with the
/// current tile object.
pub fn derive_tile(
    tile: Selector,
    dst: Selector,
    eps: Option<u32>,
    bw: Option<u32>,
    time: Option<u64>,
    pts: Option<usize>,
) -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(
        buf,
        syscalls::Operation::DERIVE_TILE,
        syscalls::DeriveTile {
            tile,
            dst,
            eps,
            bw,
            time,
            pts,
        }
    );
    send_receive_result(&buf)
}

/// Derives a new service object at `dst` + 0 and a send gate to create sessions at `dst` + 1 from
/// existing service `srv`, transferring `sessions` sessions to the new service object.
/// A non-error reply just acknowledges that the request has been sent to the service. Upon the
/// completion of the request, you will receive an upcall containing `event`.
pub fn derive_srv(srv: Selector, dst: CapRngDesc, sessions: u32, event: u64) -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(buf, syscalls::Operation::DERIVE_SRV, syscalls::DeriveSrv {
        dst,
        srv,
        sessions,
        event,
    });
    send_receive_result(&buf)
}

/// Obtains the session capability from service `srv` with session id `sid` to the given activity.
pub fn get_sess(srv: Selector, act: Selector, dst: Selector, sid: u64) -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(buf, syscalls::Operation::GET_SESS, syscalls::GetSess {
        dst,
        srv,
        act,
        sid
    });
    send_receive_result(&buf)
}

/// Returns the global address and size of the MemGate at `mgate`
pub fn mgate_region(mgate: Selector) -> Result<(GlobAddr, goff), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(
        buf,
        syscalls::Operation::MGATE_REGION,
        syscalls::MGateRegion { mgate }
    );

    let reply: Reply<syscalls::MGateRegionReply> = send_receive(&buf)?;
    Ok((reply.data.global, reply.data.size))
}

/// Returns the total and remaining quota in bytes for the kernel memory object at `kmem`.
pub fn kmem_quota(kmem: Selector) -> Result<Quota<usize>, Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(buf, syscalls::Operation::KMEM_QUOTA, syscalls::KMemQuota {
        kmem
    });

    let reply: Reply<syscalls::KMemQuotaReply> = send_receive(&buf)?;
    Ok(Quota::new(reply.data.id, reply.data.total, reply.data.left))
}

/// Returns the remaining quota (free endpoints) for the tile object at `tile`.
pub fn tile_quota(tile: Selector) -> Result<TileQuota, Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(buf, syscalls::Operation::TILE_QUOTA, syscalls::TileQuota {
        tile
    });

    let reply: Reply<syscalls::TileQuotaReply> = send_receive(&buf)?;
    Ok(TileQuota::new(
        Quota::new(reply.data.eps_id, reply.data.eps_total, reply.data.eps_left),
        Quota::new(reply.data.bw_id, reply.data.bw_total, reply.data.bw_left),
        Quota::new(
            reply.data.time_id,
            reply.data.time_total,
            reply.data.time_left,
        ),
        Quota::new(reply.data.pts_id, reply.data.pts_total, reply.data.pts_left),
    ))
}

/// Sets the quota of the tile with given selector to specified initial values (given time slice
/// length, bytes per millisecond memory bandwidth, and number of page tables). This call is only
/// permitted for root tile capabilities.
pub fn tile_set_quota(tile: Selector, bw: u32, time: u64, pts: usize) -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(
        buf,
        syscalls::Operation::TILE_SET_QUOTA,
        syscalls::TileSetQuota {
            tile,
            bw,
            time,
            pts
        }
    );
    send_receive_result(&buf)
}

/// Performs the activity operation `op` with the given activity.
pub fn activity_ctrl(act: Selector, op: syscalls::ActivityOp, arg: u64) -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(buf, syscalls::Operation::ACT_CTRL, syscalls::ActivityCtrl {
        act,
        op,
        arg
    });

    if act == kif::SEL_ACT && op == syscalls::ActivityOp::STOP {
        SGATE.borrow().send(&buf, RecvGate::syscall())
    }
    else {
        send_receive_result(&buf)
    }
}

/// Waits until any of the given activities exits.
///
/// If `event` is non-zero, the kernel replies immediately and acknowledges the validity of the
/// request and sends an upcall as soon as a activity exists. Otherwise, the kernel replies only as soon
/// as a activity exists. In both cases, the kernel returns the selector of the activity that exited and the
/// exitcode given by the activity.
pub fn activity_wait(sels: &[Selector], event: u64) -> Result<(Selector, i32), Error> {
    let mut buf = SYSC_BUF.borrow_mut();

    #[allow(clippy::uninit_assumed_init)]
    // safety: will be initialized below
    let mut acts: [Selector; syscalls::MAX_WAIT_ACTS] =
        unsafe { MaybeUninit::uninit().assume_init() };
    for (i, sel) in sels.iter().enumerate() {
        acts[i] = *sel;
    }
    build_vmsg!(buf, syscalls::Operation::ACT_WAIT, syscalls::ActivityWait {
        event,
        act_count: sels.len(),
        acts,
    });

    let reply: Reply<syscalls::ActivityWaitReply> = send_receive(&buf)?;
    if event != 0 {
        Ok((0, 0))
    }
    else {
        Ok((reply.data.act_sel, reply.data.exitcode))
    }
}

/// Performs the semaphore operation `op` with the given semaphore.
pub fn sem_ctrl(sem: Selector, op: syscalls::SemOp) -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(buf, syscalls::Operation::SEM_CTRL, syscalls::SemCtrl {
        sem,
        op
    });
    send_receive_result(&buf)
}

/// Exchanges capabilities between your activity and the activity `act`.
///
/// If `obtain` is true, the capabilities `other`..`own.count()` and copied to `own`. If `obtain` is
/// false, the capabilities `own` are copied to `other`..`own.count()`.
pub fn exchange(
    act: Selector,
    own: CapRngDesc,
    other: Selector,
    obtain: bool,
) -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(buf, syscalls::Operation::EXCHANGE, syscalls::Exchange {
        act,
        own,
        other,
        obtain,
    });
    send_receive_result(&buf)
}

/// Delegates the capabilities `crd` of activity `act` via the session `sess` to the server managing the
/// session.
///
/// `pre` and `post` are called before and after the system call, respectively. `pre` is called with
/// [`M3Serializer`], allowing to pass arguments to the server, whereas `post` is called with
/// [`M3Deserializer`], allowing to get arguments from the server.
pub fn delegate<PRE, POST>(
    act: Selector,
    sess: Selector,
    crd: CapRngDesc,
    pre: PRE,
    post: POST,
) -> Result<(), Error>
where
    PRE: Fn(&mut M3Serializer<SliceSink<'_>>),
    POST: FnMut(&mut M3Deserializer<'_>) -> Result<(), Error>,
{
    exchange_sess(act, false, sess, crd, pre, post)
}

/// Obtains `crd.count` capabilities via the session `sess` from the server managing the session
/// into `crd` of activity `act`.
///
/// `pre` and `post` are called before and after the system call, respectively. `pre` is called with
/// [`M3Serializer`], allowing to pass arguments to the server, whereas `post` is called with
/// [`M3Deserializer`], allowing to get arguments from the server.
pub fn obtain<PRE, POST>(
    act: Selector,
    sess: Selector,
    crd: CapRngDesc,
    pre: PRE,
    post: POST,
) -> Result<(), Error>
where
    PRE: Fn(&mut M3Serializer<SliceSink<'_>>),
    POST: FnMut(&mut M3Deserializer<'_>) -> Result<(), Error>,
{
    exchange_sess(act, true, sess, crd, pre, post)
}

fn exchange_sess<PRE, POST>(
    act: Selector,
    obtain: bool,
    sess: Selector,
    crd: CapRngDesc,
    pre: PRE,
    mut post: POST,
) -> Result<(), Error>
where
    PRE: Fn(&mut M3Serializer<SliceSink<'_>>),
    POST: FnMut(&mut M3Deserializer<'_>) -> Result<(), Error>,
{
    let mut buf = SYSC_BUF.borrow_mut();
    let mut args = syscalls::ExchangeArgs::default();

    {
        let mut sink = M3Serializer::new(SliceSink::new(&mut args.data));
        pre(&mut sink);
        args.bytes = sink.size();
    }

    build_vmsg!(
        buf,
        syscalls::Operation::EXCHANGE_SESS,
        syscalls::ExchangeSess {
            act,
            sess,
            crd,
            args,
            obtain,
        }
    );

    let reply: Reply<syscalls::ExchangeSessReply> = send_receive(&buf)?;

    {
        let words = (reply.data.args.bytes + 7) / 8;
        let mut src = M3Deserializer::new(&reply.data.args.data[..words]);
        post(&mut src)?;
    }

    Ok(())
}

/// Activates the given gate on given endpoint.
///
/// When activating a receive gate, the physical memory of the receive buffer and its offset needs
/// to be specified via `rbuf_mem` and `rbuf_off`.
pub fn activate(
    ep: Selector,
    gate: Selector,
    rbuf_mem: Selector,
    rbuf_off: goff,
) -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(buf, syscalls::Operation::ACTIVATE, syscalls::Activate {
        ep,
        gate,
        rbuf_mem,
        rbuf_off,
    });
    send_receive_result(&buf)
}

/// Revokes the given capabilities from given activity.
///
/// If `own` is true, they are also revoked from the given activity. Otherwise, only the delegations of
/// the capabilities are revoked.
pub fn revoke(act: Selector, crd: CapRngDesc, own: bool) -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(buf, syscalls::Operation::REVOKE, syscalls::Revoke {
        act,
        crd,
        own
    });
    send_receive_result(&buf)
}

/// The reset stats system call for benchmarking
///
/// Resets the statistics for all activities in the system
pub fn reset_stats() -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(
        buf,
        syscalls::Operation::RESET_STATS,
        syscalls::ResetStats {}
    );
    send_receive_result(&buf)
}

/// The noop system call for benchmarking
pub fn noop() -> Result<(), Error> {
    let mut buf = SYSC_BUF.borrow_mut();
    build_vmsg!(buf, syscalls::Operation::NOOP, syscalls::Noop {});
    send_receive_result(&buf)
}

pub(crate) fn init() {
    let env = crate::env::get();
    SGATE.set(SendGate::new_def(
        INVALID_SEL,
        env.first_std_ep() + SYSC_SEP_OFF,
    ));
}
