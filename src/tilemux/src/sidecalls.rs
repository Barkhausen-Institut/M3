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
use base::io::LogFlags;
use base::kif;
use base::log;
use base::mem::{GlobAddr, MsgBuf, VirtAddr, VirtAddrRaw};
use base::serialize::{Deserialize, M3Deserializer};
use base::tcu;
use base::time::TimeDuration;

use crate::activities;
use crate::helper;
use crate::quota;
use crate::sendqueue;

const SIDE_RBUF_ADDR: VirtAddr =
    VirtAddr::new(cfg::TILEMUX_RBUF_SPACE.as_raw() + cfg::KPEX_RBUF_SIZE as VirtAddrRaw);

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
        LogFlags::MuxSideCalls,
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
        LogFlags::MuxSideCalls,
        "sidecall::activity_ctrl(act={}, op={:?})",
        r.act_id,
        r.act_op,
    );

    match r.act_op {
        kif::tilemux::ActivityOp::Start => {
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
                _ => activities::remove(r.act_id, Code::Success, false, true),
            }
            Ok(())
        },
    }
}

fn map(msg: &'static tcu::Message) -> Result<(), Error> {
    let r: kif::tilemux::Map = get_request(msg)?;

    log!(
        LogFlags::MuxSideCalls,
        "sidecall::map(act={}, virt={}, glob={}, pages={}, perm={:?})",
        r.act_id,
        r.virt,
        r.global,
        r.pages,
        r.perm
    );

    // ensure that we don't overmap critical areas
    if r.virt < cfg::TILEMUX_RBUF_SPACE + cfg::TILEMUX_RBUF_SIZE
        || r.virt + r.pages * cfg::PAGE_SIZE > cfg::TILE_MEM_BASE
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

        act.map(r.virt, r.global, r.pages, perm)
    }
    else {
        Ok(())
    }
}

fn translate(msg: &'static tcu::Message) -> Result<kif::PTE, Error> {
    let r: kif::tilemux::Translate = get_request(msg)?;

    log!(
        LogFlags::MuxSideCalls,
        "sidecall::translate(act={}, virt={}, perm={:?})",
        r.act_id,
        r.virt,
        r.perm
    );

    let (phys, flags) = activities::get_mut(r.act_id)
        .unwrap()
        .translate(r.virt, r.perm | kif::PageFlags::U);
    if (flags & r.perm) == kif::PageFlags::empty() {
        Err(Error::new(Code::NoPerm))
    }
    else {
        Ok(GlobAddr::new_from_phys(phys).unwrap().raw())
    }
}

fn rem_msgs(msg: &'static tcu::Message) -> Result<(), Error> {
    let r: kif::tilemux::RemMsgs = get_request(msg)?;

    log!(
        LogFlags::MuxSideCalls,
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
        LogFlags::MuxSideCalls,
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
        LogFlags::MuxSideCalls,
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
        LogFlags::MuxSideCalls,
        "sidecall::get_quota(time={}, pts={})",
        r.time,
        r.pts
    );

    quota::get(r.time, r.pts)
}

fn set_quota(msg: &'static tcu::Message) -> Result<(), Error> {
    let r: kif::tilemux::SetQuota = get_request(msg)?;

    log!(
        LogFlags::MuxSideCalls,
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
        LogFlags::MuxSideCalls,
        "sidecall::remove_quotas(time={:?}, pts={:?})",
        r.time,
        r.pts
    );

    quota::remove(r.time, r.pts)
}

fn reset_stats(_msg: &'static tcu::Message) -> Result<(), Error> {
    log!(LogFlags::MuxSideCalls, "sidecall::reset_stats()",);

    for id in 0..64 {
        if let Some(mut act) = activities::get_mut(id) {
            act.reset_stats();
        }
    }

    Ok(())
}

fn shutdown(msg: &'static tcu::Message) -> Result<(), Error> {
    log!(LogFlags::MuxSideCalls, "sidecall::shutdown()",);

    base::machine::write_coverage(0);

    let mut reply_buf = MsgBuf::borrow_def();
    base::build_vmsg!(reply_buf, Code::Success, kif::tilemux::Response {
        val1: 0,
        val2: 0
    });
    reply_msg(msg, &reply_buf);

    // call sleep here directly after reply, so that we hopefully don't execute any code while the
    // kernel resets the tile. this is actually just a workaround for gem5, where we cannot reset
    // the core properly.
    extern "C" {
        fn start_sleep();
    }
    unsafe {
        start_sleep();
    }

    unreachable!();
}

fn handle_sidecall(msg: &'static tcu::Message) {
    let mut de = M3Deserializer::new(msg.as_words());

    let mut val1 = 0;
    let mut val2 = 0;
    let op: kif::tilemux::Sidecalls = de.pop().unwrap();
    let res = match op {
        kif::tilemux::Sidecalls::ActInit => activity_init(msg),
        kif::tilemux::Sidecalls::ActCtrl => activity_ctrl(msg),
        kif::tilemux::Sidecalls::Map => map(msg),
        kif::tilemux::Sidecalls::Translate => translate(msg).map(|pte| val1 = pte),
        kif::tilemux::Sidecalls::RemMsgs => rem_msgs(msg),
        kif::tilemux::Sidecalls::EPInval => ep_inval(msg),
        kif::tilemux::Sidecalls::DeriveQuota => derive_quota(msg).map(|(time, pts)| {
            val1 = time;
            val2 = pts;
        }),
        kif::tilemux::Sidecalls::GetQuota => {
            get_quota(msg).map(|(t_total, t_left, p_total, p_left)| {
                val1 = t_total << 32 | t_left;
                val2 = (p_total as u64) << 32 | (p_left as u64);
            })
        },
        kif::tilemux::Sidecalls::SetQuota => set_quota(msg),
        kif::tilemux::Sidecalls::RemoveQuotas => remove_quotas(msg),
        kif::tilemux::Sidecalls::ResetStats => reset_stats(msg),
        kif::tilemux::Sidecalls::Shutdown => shutdown(msg),
    };

    let mut reply_buf = MsgBuf::borrow_def();
    base::build_vmsg!(
        reply_buf,
        match res {
            Ok(_) => Code::Success,
            Err(e) => {
                log!(LogFlags::MuxSideCalls, "sidecall {:?} failed: {}", op, e);
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
