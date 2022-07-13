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
use base::serialize::{Deserialize, M3Deserializer};
use base::tcu;
use base::time::TimeDuration;

use crate::activities;
use crate::helper;
use crate::quota;
use crate::sendqueue;

const SIDE_RBUF_ADDR: usize = cfg::TILEMUX_RBUF_SPACE + cfg::KPEX_RBUF_SIZE;

fn get_request<'de, R: Deserialize<'de>>(msg: &'static tcu::Message) -> Result<R, Error> {
    let mut de = M3Deserializer::new(msg.as_words());
    de.skip(1);
    de.pop()
}

fn reply_msg(msg: &'static tcu::Message, reply: &MsgBuf) {
    let msg_off = tcu::TCU::msg_to_offset(SIDE_RBUF_ADDR, msg);
    tcu::TCU::reply(tcu::TMSIDE_REP, reply, msg_off).unwrap();
}

fn activity_init(msg: &'static tcu::Message) -> Result<(), Error> {
    let r: kif::tilemux::ActInit = get_request(msg)?;

    log!(
        crate::LOG_SIDECALLS,
        "sidecall::activity_init(act={}, bw={}, time={}, pt={}, eps_start={})",
        r.act_id,
        r.bw_quota,
        r.time_quota,
        r.pt_quota,
        r.eps_start
    );

    activities::add(r.act_id, r.bw_quota, r.time_quota, r.pt_quota, r.eps_start)
}

fn activity_ctrl(msg: &'static tcu::Message) -> Result<(), Error> {
    let r: kif::tilemux::ActivityCtrl = get_request(msg)?;

    log!(
        crate::LOG_SIDECALLS,
        "sidecall::activity_ctrl(act={}, op={:?})",
        r.act_id,
        r.act_op,
    );

    match r.act_op {
        kif::tilemux::ActivityOp::START => {
            let cur = activities::cur();
            assert!(cur.id() != r.act_id);
            let mut act = activities::get_mut(r.act_id).unwrap();
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
                Some(cur) if cur.id() == r.act_id => {
                    crate::reg_scheduling(activities::ScheduleAction::Kill)
                },
                _ => activities::remove(r.act_id, 0, false, true),
            }
            Ok(())
        },
    }
}

fn map(msg: &'static tcu::Message) -> Result<(), Error> {
    let r: kif::tilemux::Map = get_request(msg)?;

    log!(
        crate::LOG_SIDECALLS,
        "sidecall::map(act={}, virt={:#x}, global={:?}, pages={}, perm={:?})",
        r.act_id,
        r.virt,
        r.global,
        r.pages,
        r.perm
    );

    let virt = r.virt as usize;

    // ensure that we don't overmap critical areas
    if virt < cfg::TILEMUX_RBUF_SPACE + cfg::TILEMUX_RBUF_SIZE
        || virt + r.pages * cfg::PAGE_SIZE > cfg::TILE_MEM_BASE
    {
        return Err(Error::new(Code::InvArgs));
    }

    if let Some(mut act) = activities::get_mut(r.act_id) {
        // if we unmap these pages, flush+invalidate the cache to ensure that we read this memory
        // fresh from DRAM the next time we use it.
        let perm = if (r.perm & kif::PageFlags::RWX).is_empty() {
            helper::flush_cache();
            r.perm
        }
        else {
            r.perm | kif::PageFlags::U
        };

        act.map(virt, r.global, r.pages, perm)
    }
    else {
        Ok(())
    }
}

fn translate(msg: &'static tcu::Message) -> Result<kif::PTE, Error> {
    let r: kif::tilemux::Translate = get_request(msg)?;

    log!(
        crate::LOG_SIDECALLS,
        "sidecall::translate(act={}, virt={:#x}, perm={:?})",
        r.act_id,
        r.virt,
        r.perm
    );

    let pte = activities::get_mut(r.act_id)
        .unwrap()
        .translate(r.virt as usize, r.perm | kif::PageFlags::U);
    if (pte & r.perm.bits()) == 0 {
        Err(Error::new(Code::NoPerm))
    }
    else {
        Ok(GlobAddr::new_from_phys(pte).unwrap().raw())
    }
}

fn rem_msgs(msg: &'static tcu::Message) -> Result<(), Error> {
    let r: kif::tilemux::RemMsgs = get_request(msg)?;

    log!(
        crate::LOG_SIDECALLS,
        "sidecall::rem_msgs(act={}, unread={})",
        r.act_id,
        r.unread_mask
    );

    // we know that this activity is not currently running, because we changed the current activity to ourself
    // in check() below.
    if let Some(mut act) = activities::get_mut(r.act_id) {
        act.rem_msgs(r.unread_mask.count_ones() as u16);
    }

    Ok(())
}

fn ep_inval(msg: &'static tcu::Message) -> Result<(), Error> {
    let r: kif::tilemux::EpInval = get_request(msg)?;

    log!(
        crate::LOG_SIDECALLS,
        "sidecall::ep_inval(act={}, ep={})",
        r.act_id,
        r.ep
    );

    // just unblock the activity in case it wants to do something on invalidated EPs
    if let Some(mut act) = activities::get_mut(r.act_id) {
        act.unblock(activities::Event::EpInvalid);
    }

    Ok(())
}

fn derive_quota(msg: &'static tcu::Message) -> Result<(u64, u64), Error> {
    let r: kif::tilemux::DeriveQuota = get_request(msg)?;

    log!(
        crate::LOG_SIDECALLS,
        "sidecall::derive_quota(ptime={}, ppts={}, time={:?}, pts={:?})",
        r.parent_time,
        r.parent_pts,
        r.time,
        r.pts
    );

    quota::derive(
        r.parent_time,
        r.parent_pts,
        r.time.map(TimeDuration::from_nanos),
        r.pts,
    )
}

fn get_quota(msg: &'static tcu::Message) -> Result<(u64, u64, usize, usize), Error> {
    let r: kif::tilemux::GetQuota = get_request(msg)?;

    log!(
        crate::LOG_SIDECALLS,
        "sidecall::get_quota(time={}, pts={})",
        r.time,
        r.pts
    );

    quota::get(r.time, r.pts)
}

fn set_quota(msg: &'static tcu::Message) -> Result<(), Error> {
    let r: kif::tilemux::SetQuota = get_request(msg)?;

    log!(
        crate::LOG_SIDECALLS,
        "sidecall::set_quota(id={}, time={:?}, pts={})",
        r.id,
        r.time,
        r.pts
    );

    quota::set(r.id, TimeDuration::from_nanos(r.time), r.pts)
}

fn remove_quotas(msg: &'static tcu::Message) -> Result<(), Error> {
    let r: kif::tilemux::RemoveQuotas = get_request(msg)?;

    log!(
        crate::LOG_SIDECALLS,
        "sidecall::remove_quotas(time={:?}, pts={:?})",
        r.time,
        r.pts
    );

    quota::remove(r.time, r.pts)
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

fn shutdown(_msg: &'static tcu::Message) -> Result<(), Error> {
    log!(crate::LOG_SIDECALLS, "sidecall::shutdown()",);

    base::machine::write_coverage(0);

    Ok(())
}

fn handle_sidecall(msg: &'static tcu::Message) {
    let mut de = M3Deserializer::new(msg.as_words());

    let mut val1 = 0;
    let mut val2 = 0;
    let op: kif::tilemux::Sidecalls = de.pop().unwrap();
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
        kif::tilemux::Sidecalls::SHUTDOWN => shutdown(msg),
        _ => Err(Error::new(Code::NotSup)),
    };

    let mut reply_buf = MsgBuf::borrow_def();
    base::build_vmsg!(
        reply_buf,
        match res {
            Ok(_) => Code::None,
            Err(e) => {
                log!(crate::LOG_SIDECALLS, "sidecall {} failed: {}", op, e);
                e.code()
            },
        },
        kif::tilemux::Response { val1, val2 }
    );
    reply_msg(msg, &reply_buf);
}

#[inline(never)]
fn handle_sidecalls(mut our: activities::ActivityRef<'_>) {
    let _cmd_saved = helper::TCUGuard::new();

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
