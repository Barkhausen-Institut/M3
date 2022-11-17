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

use base::cfg;
use base::errors::{Code, Error};
use base::kif;
use base::log;
use base::mem::{GlobAddr, MsgBuf};
use base::tcu;
use base::time::{TimeDuration, Profiler, TimeInstant, CycleInstant};

use crate::{activities, LOG_ERR};
use crate::helper;
use crate::quota;
use crate::sendqueue;

const SIDE_RBUF_ADDR: usize = cfg::TILEMUX_RBUF_SPACE + cfg::KPEX_RBUF_SIZE;

fn reply_msg(msg: &'static tcu::Message, reply: &MsgBuf) {
    let msg_off = tcu::TCU::msg_to_offset(SIDE_RBUF_ADDR, msg);
    tcu::TCU::reply(tcu::TMSIDE_REP, reply, msg_off).unwrap();
}

fn activity_init(msg: &'static tcu::Message) -> Result<(), Error> {
    let req = msg.get_data::<kif::tilemux::ActInit>();

    let act_id = req.act_sel as activities::Id;
    let time_quota = req.time_quota as quota::Id;
    let pt_quota = req.pt_quota as quota::Id;
    let eps_start = req.eps_start as tcu::EpId;

    log!(
        crate::LOG_SIDECALLS,
        "sidecall::activity_init(act={}, time={}, pt={}, eps_start={})",
        act_id,
        time_quota,
        pt_quota,
        eps_start
    );

    // activities::add(act_id, time_quota, pt_quota, eps_start)

    Ok(())
}

fn activity_ctrl(msg: &'static tcu::Message) -> Result<(), Error> {
    let req = msg.get_data::<kif::tilemux::ActivityCtrl>();

    let act_id = req.act_sel as activities::Id;
    let op = kif::tilemux::ActivityOp::from(req.act_op);

    log!(
        crate::LOG_SIDECALLS,
        "sidecall::activity_ctrl(act={}, op={:?})",
        act_id,
        op,
    );

    match op {
        kif::tilemux::ActivityOp::START => {
            let cur = activities::cur();
            assert!(cur.id() != act_id);
            let mut act = activities::get_mut(act_id).unwrap();
            // temporary switch to the activity to access the environment
            act.switch_to();
            act.start();
            act.unblock(activities::Event::Start);
            // now switch back
            cur.switch_to();
            Ok(())
        },

        _ => {
            // we cannot remove the current activity here; remove it via scheduling
            match activities::try_cur() {
                Some(cur) if cur.id() == act_id => {
                    crate::reg_scheduling(activities::ScheduleAction::Kill)
                },
                _ => activities::remove(act_id, 0, false, true),
            }
            Ok(())
        },
    }
}

fn map(msg: &'static tcu::Message) -> Result<(), Error> {
    let req = msg.get_data::<kif::tilemux::Map>();

    let act_id = req.act_sel as activities::Id;
    let virt = req.virt as usize;
    let global = GlobAddr::new(req.global);
    let pages = req.pages as usize;
    let perm = kif::PageFlags::from_bits_truncate(req.perm as u64);

    log!(
        crate::LOG_SIDECALLS,
        "sidecall::map(act={}, virt={:#x}, global={:?}, pages={}, perm={:?})",
        act_id,
        virt,
        global,
        pages,
        perm
    );

    // ensure that we don't overmap critical areas
    if virt < cfg::ENV_START || virt + pages * cfg::PAGE_SIZE > cfg::TILE_MEM_BASE {
        return Err(Error::new(Code::InvArgs));
    }

    if let Some(mut act) = activities::get_mut(act_id) {
        // if we unmap these pages, flush+invalidate the cache to ensure that we read this memory
        // fresh from DRAM the next time we use it.
        let perm = if (perm & kif::PageFlags::RWX).is_empty() {
            helper::flush_invalidate();
            perm
        }
        else {
            perm | kif::PageFlags::U
        };

        act.map(virt, global, pages, perm)
    }
    else {
        Ok(())
    }
}

fn translate(msg: &'static tcu::Message) -> Result<kif::PTE, Error> {
    let req = msg.get_data::<kif::tilemux::Translate>();

    let act_id = req.act_sel as activities::Id;
    let virt = req.virt as usize;
    let perm = kif::PageFlags::from_bits_truncate(req.perm as u64);

    log!(
        crate::LOG_SIDECALLS,
        "sidecall::translate(act={}, virt={:#x}, perm={:?})",
        act_id,
        virt,
        perm
    );

    let pte = activities::get_mut(act_id)
        .unwrap()
        .translate(virt, perm | kif::PageFlags::U);
    if (pte & perm.bits()) == 0 {
        Err(Error::new(Code::NoPerm))
    }
    else {
        Ok(GlobAddr::new_from_phys(pte).unwrap().raw())
    }
}

fn rem_msgs(msg: &'static tcu::Message) -> Result<(), Error> {
    let req = msg.get_data::<kif::tilemux::RemMsgs>();

    let act_id = req.act_sel as activities::Id;
    let unread = req.unread_mask as u32;

    log!(
        crate::LOG_SIDECALLS,
        "sidecall::rem_msgs(act={}, unread={})",
        act_id,
        unread
    );

    // we know that this activity is not currently running, because we changed the current activity to ourself
    // in check() below.
    if let Some(mut act) = activities::get_mut(act_id) {
        act.rem_msgs(unread.count_ones() as u16);
    }

    Ok(())
}

fn ep_inval(msg: &'static tcu::Message) -> Result<(), Error> {
    let req = msg.get_data::<kif::tilemux::EpInval>();

    let act_id = req.act_sel as activities::Id;
    let ep = req.ep as tcu::EpId;

    log!(
        crate::LOG_SIDECALLS,
        "sidecall::ep_inval(act={}, ep={})",
        act_id,
        ep
    );

    // just unblock the activity in case it wants to do something on invalidated EPs
    if let Some(mut act) = activities::get_mut(act_id) {
        act.unblock(activities::Event::EpInvalid);
    }

    Ok(())
}

fn derive_quota(msg: &'static tcu::Message) -> Result<(u64, u64), Error> {
    let req = msg.get_data::<kif::tilemux::DeriveQuota>();

    let parent_time = req.parent_time as quota::Id;
    let parent_pts = req.parent_pts as quota::Id;
    let time = req.time.get::<u64>().map(TimeDuration::from_nanos);
    let pts = req.pts.get();

    log!(
        crate::LOG_SIDECALLS,
        "sidecall::derive_quota(ptime={}, ppts={}, time={:?}, pts={:?})",
        parent_time,
        parent_pts,
        time,
        pts
    );

    quota::derive(parent_time, parent_pts, time, pts)
}

fn get_quota(msg: &'static tcu::Message) -> Result<(u64, u64, usize, usize), Error> {
    let req = msg.get_data::<kif::tilemux::GetQuota>();

    let time = req.time as quota::Id;
    let pts = req.pts as quota::Id;

    log!(
        crate::LOG_SIDECALLS,
        "sidecall::get_quota(time={}, pts={})",
        time,
        pts
    );

    quota::get(time, pts)
}

fn set_quota(msg: &'static tcu::Message) -> Result<(), Error> {
    let req = msg.get_data::<kif::tilemux::SetQuota>();

    let id = req.id as quota::Id;
    let time = TimeDuration::from_nanos(req.time as u64);
    let pts = req.pts as usize;

    log!(
        crate::LOG_SIDECALLS,
        "sidecall::set_quota(id={}, time={:?}, pts={})",
        id,
        time,
        pts
    );

    quota::set(id, time, pts)
}

fn remove_quotas(msg: &'static tcu::Message) -> Result<(), Error> {
    let req = msg.get_data::<kif::tilemux::RemoveQuotas>();

    let time = req.time.get();
    let pts = req.pts.get();

    log!(
        crate::LOG_SIDECALLS,
        "sidecall::remove_quotas(time={:?}, pts={:?})",
        time,
        pts
    );

    quota::remove(time, pts)
}

fn reset_stats(_msg: &'static tcu::Message) -> Result<(), Error> {
    log!(crate::LOG_SIDECALLS, "sidecall::reset_stats()",);

    for id in 0..64 {
        if let Some(mut act) = activities::get_mut(id) {
            act.reset_stats();
        }
    }

    Ok(())
}

fn handle_sidecall(msg: &'static tcu::Message) {
    let req = msg.get_data::<kif::DefaultRequest>();

    let mut val1 = 0;
    let mut val2 = 0;
    let op = kif::tilemux::Sidecalls::from(req.opcode);
    let res = match op {
        kif::tilemux::Sidecalls::ACT_INIT => activity_init(msg),
        kif::tilemux::Sidecalls::ACT_CTRL => activity_ctrl(msg),
        kif::tilemux::Sidecalls::MAP => map(msg),
        kif::tilemux::Sidecalls::TRANSLATE => translate(msg).map(|pte| val1 = pte),
        kif::tilemux::Sidecalls::REM_MSGS => rem_msgs(msg),
        kif::tilemux::Sidecalls::EP_INVAL => ep_inval(msg),
        kif::tilemux::Sidecalls::DERIVE_QUOTA => derive_quota(msg).map(|(time, pts)| {
            val1 = time;
            val2 = pts;
        }),
        kif::tilemux::Sidecalls::GET_QUOTA => {
            get_quota(msg).map(|(t_total, t_left, p_total, p_left)| {
                val1 = t_total << 32 | t_left;
                val2 = (p_total as u64) << 32 | (p_left as u64);
            })
        },
        kif::tilemux::Sidecalls::SET_QUOTA => set_quota(msg),
        kif::tilemux::Sidecalls::REMOVE_QUOTAS => remove_quotas(msg),
        kif::tilemux::Sidecalls::RESET_STATS => reset_stats(msg),
        _ => Err(Error::new(Code::NotSup)),
    };

    let mut reply_buf = MsgBuf::borrow_def();
    reply_buf.set(kif::tilemux::Response {
        error: match res {
            Ok(_) => 0,
            Err(e) => {
                log!(crate::LOG_SIDECALLS, "sidecall {} failed: {}", op, e);
                e.code() as u64
            },
        },
        val1,
        val2,
    });
    reply_msg(msg, &reply_buf);
}


fn send_msg<T>(msg_obj: T) -> Result<(), Error> {
    let mut msg_buf = MsgBuf::borrow_def();
    msg_buf.set(msg_obj);
    tcu::TCU::send(tcu::KPEX_SEP, &msg_buf, 0, tcu::KPEX_REP)
}

fn wait_for_rpl() -> Result<(), Error> {
    loop {
        if let Some(off) = tcu::TCU::fetch_msg(tcu::KPEX_REP) {
            let msg = tcu::TCU::offset_to_msg(cfg::TILEMUX_RBUF_SPACE, off);
            let rpl = msg.get_data::<kif::DefaultReply>();
            tcu::TCU::ack_msg(tcu::KPEX_REP, off)?;
            return match rpl.error {
                0 => Ok(()),
                e =>{
                    Err((e as u32).into())
                },
            };
        }
    }
}

#[inline(never)]
fn handle_sidecalls(mut our: activities::ActivityRef<'_>) {
    let _cmd_saved = helper::TCUGuard::new();
    log!(LOG_ERR, "handle sidecalls");
    loop {
        // change to our activity
        let old_act = tcu::TCU::xchg_activity(our.activity_reg()).unwrap();
        if let Some(mut old) = activities::try_cur() {
            old.set_activity_reg(old_act);
        }

        if let Some(msg_off) = tcu::TCU::fetch_msg(tcu::TMSIDE_REP) {
            let msg = tcu::TCU::offset_to_msg(SIDE_RBUF_ADDR, msg_off);
            handle_sidecall(msg);
        }

        // check if the kernel answered a request from us
        sendqueue::check_replies();


        let msg = kif::tilemux::Exit {
            op: kif::tilemux::Calls::EXIT.val,
            act_sel: 1,
            code: 1,
        };

        // benchmark
        let mut profiler = Profiler::default().repeats(1000);
        log!(LOG_ERR, "{}", profiler.run::<CycleInstant, _>(|| {
            send_msg(msg).unwrap();
            wait_for_rpl().unwrap();
        }));
        log!(LOG_ERR, "{}", profiler.run::<TimeInstant, _>(|| {
            send_msg(msg).unwrap();
            wait_for_rpl().unwrap();
        }));
        log!(LOG_ERR, "done");
        loop {}

        // change back to old activity
        let new_act = activities::try_cur().map_or(old_act, |new| new.activity_reg());
        our.set_activity_reg(tcu::TCU::xchg_activity(new_act).unwrap());
        // if no events arrived in the meantime, we're done
        if !our.has_msgs() {
            break;
        }
    }
}

#[inline(always)]
pub fn check() {
    let our = activities::our();
    if !our.has_msgs() {
        return;
    }

    handle_sidecalls(our);
}
