/*
 * Copyright (C) 2020-2022 Nils Asmussen, Barkhausen Institut
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

use base::build_vmsg;
use base::cfg;
use base::col::ToString;
use base::errors::{Code, VerboseError};
use base::kif::{self, syscalls};
use base::mem::{GlobOff, MsgBuf, PhysAddr, PhysAddrRaw};
use base::rc::Rc;
use base::tcu;

use crate::cap::{Capability, KObject};
use crate::cap::{EPObject, SemObject};
use crate::ktcu;
use crate::platform;
use crate::syscalls::{get_request, reply_success, send_reply};
use crate::tiles::{tilemng, Activity};

#[inline(never)]
pub fn alloc_ep(act: &Rc<Activity>, msg: &'static tcu::Message) -> Result<(), VerboseError> {
    let r: syscalls::AllocEP = get_request(msg)?;
    sysc_log!(
        act,
        "alloc_ep(dst={}, act={}, epid={}, replies={})",
        r.dst,
        r.act,
        r.epid,
        r.replies
    );

    if !act.obj_caps().borrow().unused(r.dst) {
        sysc_err!(Code::InvArgs, "Selector {} already in use", r.dst);
    }
    if r.replies >= tcu::AVAIL_EPS as u32 {
        sysc_err!(Code::InvArgs, "Invalid reply count ({})", r.replies);
    }

    let ep_count = 1 + r.replies;
    let dst_act = get_kobj!(act, r.act, Activity).upgrade().unwrap();
    if !dst_act.tile().has_quota(ep_count) {
        sysc_err!(
            Code::NoSpace,
            "Tile cap has insufficient EPs (have {}, need {})",
            dst_act.tile().ep_quota().left(),
            ep_count
        );
    }

    let mut tilemux = tilemng::tilemux(dst_act.tile_id());
    let epid = if r.epid == tcu::TOTAL_EPS {
        match tilemux.find_eps(ep_count) {
            Ok(epid) => epid,
            Err(e) => sysc_err!(e.code(), "No free EP range for {} EPs", ep_count),
        }
    }
    else {
        if r.epid > tcu::AVAIL_EPS || r.epid as u32 + ep_count > tcu::AVAIL_EPS as u32 {
            sysc_err!(
                Code::InvArgs,
                "Invalid endpoint id ({}:{})",
                r.epid,
                ep_count
            );
        }
        if !tilemux.eps_free(r.epid, ep_count) {
            sysc_err!(
                Code::InvArgs,
                "Endpoints {}..{} not free",
                r.epid,
                r.epid as u32 + ep_count - 1
            );
        }
        r.epid
    };

    let cap = Capability::new(
        r.dst,
        KObject::EP(EPObject::new(
            false,
            Rc::downgrade(&dst_act),
            epid,
            r.replies,
            dst_act.tile(),
        )),
    );
    try_kmem_quota!(act.obj_caps().borrow_mut().insert_as_child(cap, r.act));

    dst_act.tile().alloc_eps(ep_count);
    tilemux.alloc_eps(epid, ep_count);

    let mut kreply = MsgBuf::borrow_def();
    build_vmsg!(kreply, Code::Success, kif::syscalls::AllocEPReply {
        ep: epid
    });
    send_reply(msg, &kreply);

    Ok(())
}

#[inline(never)]
pub fn mgate_region(act: &Rc<Activity>, msg: &'static tcu::Message) -> Result<(), VerboseError> {
    let r: syscalls::MGateRegion = get_request(msg)?;
    sysc_log!(act, "mgate_addr(mgate={})", r.mgate);

    let act_caps = act.obj_caps().borrow();
    let mgate = get_kobj_ref!(act_caps, r.mgate, MGate);

    let mut kreply = MsgBuf::borrow_def();
    build_vmsg!(kreply, Code::Success, kif::syscalls::MGateRegionReply {
        global: mgate.addr(),
        size: mgate.size(),
    });
    send_reply(msg, &kreply);

    Ok(())
}

#[inline(never)]
pub fn rgate_buffer(act: &Rc<Activity>, msg: &'static tcu::Message) -> Result<(), VerboseError> {
    let r: syscalls::RGateBuffer = get_request(msg)?;
    sysc_log!(act, "rgate_buffer(rgate={})", r.rgate);

    let act_caps = act.obj_caps().borrow();
    let rgate = get_kobj_ref!(act_caps, r.rgate, RGate);

    let mut kreply = MsgBuf::borrow_def();
    build_vmsg!(kreply, Code::Success, kif::syscalls::RGateBufferReply {
        order: rgate.order(),
        msg_order: rgate.msg_order(),
    });
    send_reply(msg, &kreply);

    Ok(())
}

#[inline(never)]
pub fn kmem_quota(act: &Rc<Activity>, msg: &'static tcu::Message) -> Result<(), VerboseError> {
    let r: syscalls::KMemQuota = get_request(msg)?;
    sysc_log!(act, "kmem_quota(kmem={})", r.kmem);

    let act_caps = act.obj_caps().borrow();
    let kmem = get_kobj_ref!(act_caps, r.kmem, KMem);

    let mut kreply = MsgBuf::borrow_def();
    build_vmsg!(kreply, Code::Success, kif::syscalls::KMemQuotaReply {
        id: kmem.id(),
        total: kmem.quota(),
        left: kmem.left(),
    });
    send_reply(msg, &kreply);

    Ok(())
}

#[inline(never)]
pub fn get_sess(act: &Rc<Activity>, msg: &'static tcu::Message) -> Result<(), VerboseError> {
    let r: syscalls::GetSess = get_request(msg)?;
    sysc_log!(
        act,
        "get_sess(dst={}, srv={}, act={}, sid={})",
        r.dst,
        r.srv,
        r.act,
        r.sid
    );

    let actcap = get_kobj!(act, r.act, Activity).upgrade().unwrap();
    if !actcap.obj_caps().borrow().unused(r.dst) {
        sysc_err!(Code::InvArgs, "Selector {} already in use", r.dst);
    }
    if Rc::ptr_eq(act, &actcap) {
        sysc_err!(Code::InvArgs, "Cannot get session for own Activity");
    }

    // get service cap
    let mut act_caps = act.obj_caps().borrow_mut();
    let srvcap = act_caps
        .get_mut(r.srv)
        .ok_or_else(|| VerboseError::new(Code::InvArgs, "Invalid capability".to_string()))?;
    let creator = as_obj!(srvcap.get(), Serv).creator();

    // find root service cap
    let srv_root = srvcap.get_root();

    // walk through the childs to find the session with given id (only root cap can create sessions)
    let mut csess =
        srv_root.find_child(|c| matches!(c.get(), KObject::Sess(s) if s.ident() == r.sid));
    if let Some(KObject::Sess(s)) = csess.as_mut().map(|c| c.get()) {
        if s.creator() != creator {
            sysc_err!(Code::NoPerm, "Cannot get access to foreign session");
        }

        try_kmem_quota!(
            actcap
                .obj_caps()
                .borrow_mut()
                .obtain(r.dst, csess.unwrap(), true)
        );
    }
    else {
        sysc_err!(Code::InvArgs, "Unknown session id {}", r.sid);
    }

    reply_success(msg);
    Ok(())
}

#[inline(never)]
pub fn activate_async(act: &Rc<Activity>, msg: &'static tcu::Message) -> Result<(), VerboseError> {
    let r: syscalls::Activate = get_request(msg)?;
    sysc_log!(
        act,
        "activate(ep={}, gate={}, rbuf_mem={}, rbuf_off={:#x})",
        r.ep,
        r.gate,
        r.rbuf_mem,
        r.rbuf_off,
    );

    let ep = get_kobj!(act, r.ep, EP);

    // activity that is currently active on the endpoint
    let ep_act = ep.activity().unwrap();

    let epid = ep.ep();
    let dst_tile = ep.tile_id();

    let invalidated = match ep.deconfigure(false) {
        Ok(inv) => inv,
        Err(e) => sysc_err!(e.code(), "Invalidation of EP {}:{} failed", dst_tile, epid),
    };

    let maybe_kobj = act
        .obj_caps()
        .borrow()
        .get(r.gate)
        .map(|cap| cap.get().clone());

    if let Some(kobj) = maybe_kobj {
        match kobj {
            KObject::MGate(_) | KObject::SGate(_) => {
                if ep.replies() != 0 {
                    sysc_err!(Code::InvArgs, "Only rgates use EP caps with reply slots");
                }
                if r.rbuf_off != 0 || r.rbuf_mem != kif::INVALID_SEL {
                    sysc_err!(Code::InvArgs, "Only rgates specify receive buffers");
                }
            },
            _ => {},
        }

        match kobj {
            KObject::MGate(ref mg) => {
                if mg.gate_ep().get_ep().is_some() {
                    sysc_err!(Code::Exists, "MemGate is already activated");
                }

                let tile_id = mg.tile_id();
                if let Err(e) =
                    tilemng::tilemux(dst_tile).config_mem_ep(epid, ep_act.id(), mg, tile_id)
                {
                    sysc_err!(e.code(), "Unable to configure mem EP");
                }
            },

            KObject::SGate(ref sg) => {
                if sg.gate_ep().get_ep().is_some() {
                    sysc_err!(Code::Exists, "SendGate is already activated");
                }

                let rgate = sg.rgate().clone();

                if !rgate.activated() {
                    sysc_log!(act, "activate: waiting for rgate {:?}", rgate);

                    let event = rgate.get_event();
                    thread::wait_for(event);

                    sysc_log!(act, "activate: rgate {:?} is activated", rgate);
                }

                if let Err(e) = tilemng::tilemux(dst_tile).config_snd_ep(epid, ep_act.id(), sg) {
                    sysc_err!(e.code(), "Unable to configure send EP");
                }
            },

            KObject::RGate(ref rg) => {
                if rg.activated() {
                    sysc_err!(Code::Exists, "RecvGate is already activated");
                }

                // determine receive buffer address
                let rbuf_addr = if platform::tile_desc(dst_tile).has_virtmem()
                    && epid == ep_act.eps_start() + tcu::PG_REP_OFF
                {
                    // special case for activating the pager reply rgate: there is no way to get a
                    // memory capability to the standard receive buffer. thus, we just determine the
                    // physical address here and remove the choice for the user.
                    ep_act.rbuf_addr()
                        + cfg::SYSC_RBUF_SIZE as PhysAddrRaw
                        + cfg::UPCALL_RBUF_SIZE as PhysAddrRaw
                        + cfg::DEF_RBUF_SIZE as PhysAddrRaw
                }
                else if platform::tile_desc(dst_tile).has_virtmem() {
                    let rbuf = get_kobj!(act, r.rbuf_mem, MGate);
                    if r.rbuf_off >= rbuf.size() || r.rbuf_off + rg.size() as GlobOff > rbuf.size()
                    {
                        sysc_err!(Code::InvArgs, "Invalid receive buffer memory");
                    }
                    if platform::tile_desc(rbuf.tile_id()).tile_type() != kif::TileType::Mem {
                        sysc_err!(Code::InvArgs, "rbuffer not in physical memory");
                    }
                    let rbuf_phys =
                        ktcu::glob_to_phys_remote(dst_tile, rbuf.addr(), kif::PageFlags::RW)
                            .map_err(|e| {
                                VerboseError::new(
                                    e.code(),
                                    base::format!(
                                        "Receive buffer at {} not accessible via PMP",
                                        rbuf.addr()
                                    ),
                                )
                            })?;
                    rbuf_phys + r.rbuf_off as PhysAddrRaw
                }
                else {
                    if r.rbuf_mem != kif::INVALID_SEL {
                        sysc_err!(Code::InvArgs, "rbuffer mem cap given for SPM tile");
                    }
                    PhysAddr::new_raw(r.rbuf_off as PhysAddrRaw)
                };

                let replies = if ep.replies() > 0 {
                    let slots = 1 << (rg.order() - rg.msg_order());
                    if ep.replies() != slots {
                        sysc_err!(
                            Code::InvArgs,
                            "EP cap has {} reply slots, need {}",
                            ep.replies(),
                            slots
                        );
                    }
                    Some(epid + 1)
                }
                else {
                    None
                };

                rg.activate(ep_act.tile_id(), epid, rbuf_addr);

                if let Err(e) =
                    tilemng::tilemux(dst_tile).config_rcv_ep(epid, ep_act.id(), replies, rg)
                {
                    rg.deactivate();
                    sysc_err!(e.code(), "Unable to configure recv EP");
                }
            },

            _ => sysc_err!(Code::InvArgs, "Invalid capability"),
        };

        EPObject::configure(&ep, &kobj);
    }
    else if !invalidated {
        if let Err(e) =
            tilemng::tilemux(dst_tile).invalidate_ep(ep_act.id(), epid, !ep.is_rgate(), true)
        {
            sysc_err!(e.code(), "Invalidation of EP {}:{} failed", dst_tile, epid);
        }
    }

    reply_success(msg);
    Ok(())
}

#[inline(never)]
pub fn sem_ctrl_async(act: &Rc<Activity>, msg: &'static tcu::Message) -> Result<(), VerboseError> {
    let r: syscalls::SemCtrl = get_request(msg)?;
    sysc_log!(act, "sem_ctrl(sem={}, op={:?})", r.sem, r.op);

    let sem = get_kobj!(act, r.sem, Sem);

    match r.op {
        kif::syscalls::SemOp::Up => {
            sem.up();
        },

        kif::syscalls::SemOp::Down => {
            let res = SemObject::down_async(&sem);
            sysc_log!(act, "sem_ctrl-cont(res={:?})", res);
            if let Err(e) = res {
                sysc_err!(e.code(), "Semaphore operation failed");
            }
        },
    }

    reply_success(msg);
    Ok(())
}

#[inline(never)]
pub fn activity_ctrl_async(
    act: &Rc<Activity>,
    msg: &'static tcu::Message,
) -> Result<(), VerboseError> {
    let r: syscalls::ActivityCtrl = get_request(msg)?;
    sysc_log!(
        act,
        "activity_ctrl(act={}, op={:?}, arg={:#x})",
        r.act,
        r.op,
        r.arg
    );

    let actcap = get_kobj!(act, r.act, Activity).upgrade().unwrap();

    match r.op {
        kif::syscalls::ActivityOp::Start => {
            if Rc::ptr_eq(act, &actcap) {
                sysc_err!(Code::InvArgs, "Activity can't start itself");
            }

            if let Err(e) = actcap.start_app_async() {
                sysc_err!(e.code(), "Unable to start Activity");
            }
        },

        kif::syscalls::ActivityOp::Stop => {
            let is_self = r.act == kif::SEL_ACT;
            actcap.stop_app_async(Code::from(r.arg as u32), is_self, act.id());
            if is_self {
                ktcu::ack_msg(ktcu::KSYS_EP, msg);
                return Ok(());
            }
        },
    };

    reply_success(msg);
    Ok(())
}

#[inline(never)]
pub fn activity_wait_async(
    act: &Rc<Activity>,
    msg: &'static tcu::Message,
) -> Result<(), VerboseError> {
    let r: syscalls::ActivityWait = get_request(msg)?;
    sysc_log!(
        act,
        "activity_wait(activities={}, event={})",
        r.act_count,
        r.event
    );

    let mut reply_msg = kif::syscalls::ActivityWaitReply {
        act_sel: kif::INVALID_SEL,
        exitcode: Code::Success,
    };

    // In any case, check whether a activity already exited. If event == 0, wait until that happened.
    // For event != 0, remember that we want to get notified and send an upcall on a activity's exit.
    if let Some((sel, code)) = act.wait_exit_async(r.event, &r.acts[0..r.act_count]) {
        sysc_log!(act, "act_wait-cont(act={}, exitcode={:?})", sel, code);

        reply_msg.act_sel = sel;
        reply_msg.exitcode = code;
    }

    let mut reply = MsgBuf::borrow_def();
    build_vmsg!(reply, Code::Success, reply_msg);
    send_reply(msg, &reply);

    Ok(())
}

pub fn reset_stats(act: &Rc<Activity>, msg: &'static tcu::Message) -> Result<(), VerboseError> {
    sysc_log!(act, "reset_stats()",);

    for tile in platform::user_tiles() {
        // ignore failures in case the TileMux is not available
        tilemng::tilemux(tile).reset_stats().ok();
    }

    reply_success(msg);
    Ok(())
}

pub fn noop(act: &Rc<Activity>, msg: &'static tcu::Message) -> Result<(), VerboseError> {
    sysc_log!(act, "noop()",);

    reply_success(msg);
    Ok(())
}
