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

use base::cell::RefMut;
use base::col::{BitVec, Vec};
use base::errors::{Code, Error};
use base::goff;
use base::kif;
use base::mem::GlobAddr;
use base::mem::MsgBuf;
use base::quota;
use base::rc::{Rc, SRc, Weak};
use base::tcu::{self, ActId, EpId, TileId};
use core::cmp;

use crate::cap::{
    EPObject, EPQuota, KMemObject, MGateObject, RGateObject, SGateObject, TileObject,
};
use crate::platform;
use crate::tiles::INVAL_ID;
use crate::ktcu;

use super::Activity;

pub struct TileMux {
    tile: SRc<TileObject>,
    acts: Vec<ActId>,
    #[cfg(not(target_vendor = "host"))]
    queue: base::boxed::Box<crate::com::SendQueue>,
    pmp: Vec<Rc<EPObject>>,
    eps: BitVec,
}

impl TileMux {
    pub fn new(tile: TileId) -> Self {
        let tile_obj = TileObject::new(
            tile,
            EPQuota::new((tcu::AVAIL_EPS - tcu::FIRST_USER_EP) as u32),
            kif::tilemux::DEF_QUOTA_ID,
            kif::tilemux::DEF_QUOTA_ID,
            false,
        );

        // create PMP EPObjects for this Tile
        let mut pmp = Vec::new();
        for ep in 0..tcu::PMEM_PROT_EPS as EpId {
            pmp.push(EPObject::new(false, Weak::new(), ep, 0, &tile_obj));
        }

        let mut tilemux = TileMux {
            tile: tile_obj,
            acts: Vec::new(),
            #[cfg(not(target_vendor = "host"))]
            queue: crate::com::SendQueue::new(crate::com::QueueId::TileMux(tile), tile),
            pmp,
            eps: BitVec::new(tcu::AVAIL_EPS as usize),
        };

        #[cfg(not(target_vendor = "host"))]
        tilemux.eps.set(0); // first EP is reserved for TileMux's memory region

        for ep in tcu::PMEM_PROT_EPS as EpId..tcu::FIRST_USER_EP {
            tilemux.eps.set(ep as usize);
        }

        #[cfg(not(target_vendor = "host"))]
        if platform::tile_desc(tile).supports_tilemux() {
            tilemux.init();
        }

        tilemux
    }

    pub fn has_activities(&self) -> bool {
        !self.acts.is_empty()
    }

    pub fn add_activity(&mut self, act: ActId) {
        self.acts.push(act);
    }

    pub fn rem_activity(&mut self, act: ActId) {
        assert!(!self.acts.is_empty());
        self.acts.retain(|id| *id != act);
    }

    #[cfg(not(target_vendor = "host"))]
    fn init(&mut self) {
        use base::cfg;

        // configure send EP
        ktcu::config_remote_ep(self.tile_id(), tcu::KPEX_SEP, |regs| {
            ktcu::config_send(
                regs,
                kif::tilemux::ACT_ID as ActId,
                self.tile_id() as tcu::Label,
                platform::kernel_tile(),
                ktcu::KPEX_EP,
                cfg::KPEX_RBUF_ORD,
                1,
            );
        })
        .unwrap();

        // configure receive EP
        let mut rbuf = platform::rbuf_tilemux(self.tile_id());
        ktcu::config_remote_ep(self.tile_id(), tcu::KPEX_REP, |regs| {
            ktcu::config_recv(
                regs,
                kif::tilemux::ACT_ID as ActId,
                rbuf,
                cfg::KPEX_RBUF_ORD,
                cfg::KPEX_RBUF_ORD,
                None,
            );
        })
        .unwrap();
        rbuf += 1 << cfg::KPEX_RBUF_ORD;

        // configure upcall EP
        ktcu::config_remote_ep(self.tile_id(), tcu::TMSIDE_REP, |regs| {
            ktcu::config_recv(
                regs,
                kif::tilemux::ACT_ID as ActId,
                rbuf,
                cfg::TMUP_RBUF_ORD,
                cfg::TMUP_RBUF_ORD,
                Some(tcu::TMSIDE_RPLEP),
            );
        })
        .unwrap();
    }

    pub fn tile(&self) -> &SRc<TileObject> {
        &self.tile
    }

    pub fn tile_id(&self) -> TileId {
        self.tile.tile()
    }

    pub fn pmp_ep(&self, ep: EpId) -> &Rc<EPObject> {
        &self.pmp[ep as usize]
    }

    pub fn find_eps(&self, count: u32) -> Result<EpId, Error> {
        // the PMP EPs cannot be allocated
        let mut start = cmp::max(tcu::FIRST_USER_EP as usize, self.eps.first_clear());
        let mut bit = start;
        while bit < start + count as usize && bit < tcu::AVAIL_EPS as usize {
            if self.eps.is_set(bit) {
                start = bit + 1;
            }
            bit += 1;
        }

        if bit != start + count as usize {
            Err(Error::new(Code::NoSpace))
        }
        else {
            Ok(start as EpId)
        }
    }

    pub fn eps_free(&self, start: EpId, count: u32) -> bool {
        for ep in start..start + count as EpId {
            if self.eps.is_set(ep as usize) {
                return false;
            }
        }
        true
    }

    pub fn alloc_eps(&mut self, start: EpId, count: u32) {
        klog!(
            EPS,
            "TileMux[{}] allocating EPS {}..{}",
            self.tile_id(),
            start,
            start as u32 + count - 1
        );
        for bit in start..start + count as EpId {
            assert!(!self.eps.is_set(bit as usize));
            self.eps.set(bit as usize);
        }
    }

    pub fn free_eps(&mut self, start: EpId, count: u32) {
        klog!(
            EPS,
            "TileMux[{}] freeing EPS {}..{}",
            self.tile_id(),
            start,
            start as u32 + count - 1
        );
        for bit in start..start + count as EpId {
            assert!(self.eps.is_set(bit as usize));
            self.eps.clear(bit as usize);
        }
    }

    fn ep_activity_id(&self, act: ActId) -> ActId {
        match platform::is_shared(self.tile_id()) {
            true => act,
            false => INVAL_ID,
        }
    }

    pub fn config_snd_ep(
        &mut self,
        ep: EpId,
        act: ActId,
        obj: &SRc<SGateObject>,
    ) -> Result<(), Error> {
        let rgate = obj.rgate();
        assert!(rgate.activated());

        klog!(EPS, "Tile{}:EP{} = {:?}", self.tile_id(), ep, obj);

        ktcu::config_remote_ep(self.tile_id(), ep, |regs| {
            let act = self.ep_activity_id(act);
            let (rpe, rep) = rgate.location().unwrap();
            ktcu::config_send(
                regs,
                act,
                obj.label(),
                rpe,
                rep,
                rgate.msg_order(),
                obj.credits(),
            );
        })
    }

    pub fn config_rcv_ep(
        &mut self,
        ep: EpId,
        act: ActId,
        reply_eps: Option<EpId>,
        obj: &SRc<RGateObject>,
    ) -> Result<(), Error> {
        klog!(EPS, "Tile{}:EP{} = {:?}", self.tile_id(), ep, obj);

        ktcu::config_remote_ep(self.tile_id(), ep, |regs| {
            let act = self.ep_activity_id(act);
            ktcu::config_recv(
                regs,
                act,
                obj.addr(),
                obj.order(),
                obj.msg_order(),
                reply_eps,
            );
        })?;

        thread::notify(obj.get_event(), None);
        Ok(())
    }

    pub fn config_mem_ep(
        &mut self,
        ep: EpId,
        act: ActId,
        obj: &SRc<MGateObject>,
        tile_id: TileId,
    ) -> Result<(), Error> {
        if ep < tcu::PMEM_PROT_EPS as EpId {
            klog!(EPS, "Tile{}:PMPEP{} = {:?}", self.tile_id(), ep, obj);
        }
        else {
            klog!(EPS, "Tile{}:EP{} = {:?}", self.tile_id(), ep, obj);
        }

        ktcu::config_remote_ep(self.tile_id(), ep, |regs| {
            let act = self.ep_activity_id(act);
            ktcu::config_mem(
                regs,
                act,
                tile_id,
                obj.offset(),
                obj.size() as usize,
                obj.perms(),
            );
        })
    }

    pub fn invalidate_ep(
        &mut self,
        act: ActId,
        ep: EpId,
        force: bool,
        notify: bool,
    ) -> Result<(), Error> {
        klog!(EPS, "Tile{}:EP{} = invalid", self.tile_id(), ep);

        let unread = ktcu::invalidate_ep_remote(self.tile_id(), ep, force)?;
        if unread != 0 && notify {
            let mut msg = MsgBuf::borrow_def();
            msg.set(kif::tilemux::RemMsgs {
                op: kif::tilemux::Sidecalls::REM_MSGS.val as u64,
                act_sel: act as u64,
                unread_mask: unread as u64,
            });

            self.send_sidecall::<kif::tilemux::RemMsgs>(Some(act), &msg)
                .map(|_| ())
        }
        else {
            Ok(())
        }
    }

    pub fn invalidate_reply_eps(
        &self,
        recv_tile: TileId,
        recv_ep: EpId,
        send_ep: EpId,
    ) -> Result<(), Error> {
        klog!(
            EPS,
            "Tile{}:EP{} = invalid reply EPs at Tile{}:EP{}",
            self.tile_id(),
            send_ep,
            recv_tile,
            recv_ep
        );

        ktcu::inv_reply_remote(recv_tile, recv_ep, self.tile_id(), send_ep)
    }

    pub fn reset_stats(&mut self) -> Result<(), Error> {
        let mut msg = MsgBuf::borrow_def();
        msg.set(kif::tilemux::ResetStats {
            op: kif::tilemux::Sidecalls::RESET_STATS.val as u64,
        });

        self.send_sidecall::<kif::tilemux::ResetStats>(None, &msg)
            .map(|_| ())
    }
}

#[cfg(not(target_vendor = "host"))]
impl TileMux {
    pub fn handle_call_async(tilemux: RefMut<'_, Self>, msg: &tcu::Message) {
        let req = msg.get_data::<kif::DefaultRequest>();
        match kif::tilemux::Calls::from(req.opcode) {
            kif::tilemux::Calls::EXIT => Self::handle_exit_sidecall(tilemux, msg),
            kif::tilemux::Calls::LX_ACT => Self::handle_lx_act_sidecall(tilemux, msg),
            kif::tilemux::Calls::NOOP => Self::handle_noop_sidecall(tilemux, msg),
            _ => panic!("Unexpected operation: {}", { req.opcode }),
        }
    }

    fn handle_exit_sidecall(tilemux: RefMut<'_, Self>, msg: &tcu::Message) {
        use crate::tiles::ActivityMng;

        let req = msg.get_data::<kif::tilemux::Exit>();
        let act_id = req.act_sel as ActId;
        let exitcode = req.code as i32;

        klog!(TMC, "TileMux[{}] received {:?}", tilemux.tile_id(), req);

        let has_act = tilemux.acts.contains(&act_id);
        drop(tilemux);

        if has_act {
            let act = ActivityMng::activity(act_id).unwrap();
            act.stop_app_async(exitcode, true);
        }

        let mut reply = MsgBuf::borrow_def();
        reply.set(kif::DefaultReply { error: 0 });
        ktcu::reply(ktcu::KPEX_EP, &reply, msg).unwrap();
    }

    fn create_lx_activity(tilemux: RefMut<'_, Self>) -> Result<Rc<Activity>, Error> {
        use crate::tiles::{ActivityMng, ActivityFlags, State};
        use base::cfg;
        use crate::args;
        use base::envdata::EnvData;

        let kmem = KMemObject::new(args::get().kmem - cfg::FIXED_KMEM);
        let tile = tilemux.tile().clone();
        drop(tilemux);
        let act = ActivityMng::create_activity_async(
            "lx_act",
            tile,
            tcu::FIRST_USER_EP,
            kmem,
            ActivityFlags::IS_LINUX,
        )?;
        // let rbuf_virt = platform::tile_desc(self.tile_id()).rbuf_std_space().0;
        act.init_eps_async(0x1040_0000)?;

        // initialize env data
        let mut env = EnvData::default();
        env.tile_id = act.tile_id() as u64;
        env.tile_desc = act.tile_desc().value();
        env.first_std_ep = act.eps_start() as u64;
        env.first_sel = act.first_sel();
        env.act_id = act.id() as u64;

        ktcu::write_mem(act.tile_id(), cfg::ENV_START as u64, &env as *const _ as *const u8, base::mem::size_of_val(&env));

        act.set_state(State::RUNNING);
        Ok(act)
    }

    fn handle_lx_act_sidecall(tilemux: RefMut<'_, Self>, msg: &tcu::Message) {
        let req = msg.get_data::<kif::tilemux::LxAct>();
        klog!(TMC, "TileMux[{}] received {:?}", tilemux.tile_id(), req);
        let act = Self::create_lx_activity(tilemux);

        let error = match act {
            Ok(act) => 0,
            Err(e) => e.code() as u64,
        };
        let mut reply = MsgBuf::borrow_def();
        reply.set(kif::DefaultReply { error });
        ktcu::reply(ktcu::KPEX_EP, &reply, msg).unwrap();
    }

    fn handle_noop_sidecall(tilemux: RefMut<'_, Self>, msg: &tcu::Message) {
        let req = msg.get_data::<kif::tilemux::Noop>();
        klog!(TMC, "TileMux[{}] received {:?}", tilemux.tile_id(), req);
        drop(tilemux);

        let mut reply = MsgBuf::borrow_def();
        reply.set(kif::DefaultReply { error: 0 });
        ktcu::reply(ktcu::KPEX_EP, &reply, msg).unwrap();
    }

    pub fn activity_init_async(
        tilemux: RefMut<'_, Self>,
        act: ActId,
        time_quota: quota::Id,
        pt_quota: quota::Id,
        eps_start: EpId,
    ) -> Result<(), Error> {
        let mut msg = MsgBuf::borrow_def();
        msg.set(kif::tilemux::ActInit {
            op: kif::tilemux::Sidecalls::ACT_INIT.val as u64,
            act_sel: act as u64,
            time_quota,
            pt_quota,
            eps_start: eps_start as u64,
        });

        Self::send_receive_sidecall_async::<kif::tilemux::ActInit>(tilemux, None, msg).map(|_| ())
    }

    pub fn activity_ctrl_async(
        tilemux: RefMut<'_, Self>,
        act: ActId,
        ctrl: base::kif::tilemux::ActivityOp,
    ) -> Result<(), Error> {
        let mut msg = MsgBuf::borrow_def();
        msg.set(kif::tilemux::ActivityCtrl {
            op: kif::tilemux::Sidecalls::ACT_CTRL.val as u64,
            act_sel: act as u64,
            act_op: ctrl.val as u64,
        });

        Self::send_receive_sidecall_async::<kif::tilemux::ActivityCtrl>(tilemux, None, msg)
            .map(|_| ())
    }

    pub fn derive_quota_async(
        tilemux: RefMut<'_, Self>,
        parent_time: quota::Id,
        parent_pts: quota::Id,
        time: Option<u64>,
        pts: Option<u64>,
    ) -> Result<(quota::Id, quota::Id), Error> {
        let mut msg = MsgBuf::borrow_def();
        msg.set(kif::tilemux::DeriveQuota {
            op: kif::tilemux::Sidecalls::DERIVE_QUOTA.val as u64,
            parent_time,
            parent_pts,
            time: kif::OptionalValue::new(time),
            pts: kif::OptionalValue::new(pts),
        });

        Self::send_receive_sidecall_async::<kif::tilemux::DeriveQuota>(tilemux, None, msg)
            .map(|r| (r.val1 as quota::Id, r.val2 as quota::Id))
    }

    pub fn get_quota_async(
        tilemux: RefMut<'_, Self>,
        time: quota::Id,
        pts: quota::Id,
    ) -> Result<(quota::Quota<u64>, quota::Quota<usize>), Error> {
        let mut msg = MsgBuf::borrow_def();
        msg.set(kif::tilemux::GetQuota {
            op: kif::tilemux::Sidecalls::GET_QUOTA.val as u64,
            time,
            pts,
        });

        let tile_id = (tilemux.tile.tile() as quota::Id) << 8;
        Self::send_receive_sidecall_async::<kif::tilemux::GetQuota>(tilemux, None, msg).map(|r| {
            (
                quota::Quota::new(
                    tile_id | time,
                    (r.val1 >> 32) as u64,
                    (r.val1 & 0xFFFF_FFFF) as u64,
                ),
                quota::Quota::new(
                    tile_id | pts,
                    (r.val2 >> 32) as usize,
                    (r.val2 & 0xFFFF_FFFF) as usize,
                ),
            )
        })
    }

    pub fn set_quota_async(
        tilemux: RefMut<'_, Self>,
        id: quota::Id,
        time: u64,
        pts: u64,
    ) -> Result<(), Error> {
        let mut msg = MsgBuf::borrow_def();
        msg.set(kif::tilemux::SetQuota {
            op: kif::tilemux::Sidecalls::SET_QUOTA.val as u64,
            id,
            time,
            pts,
        });

        Self::send_receive_sidecall_async::<kif::tilemux::SetQuota>(tilemux, None, msg).map(|_| ())
    }

    pub fn remove_quotas_async(
        tilemux: RefMut<'_, Self>,
        time: Option<quota::Id>,
        pts: Option<quota::Id>,
    ) -> Result<(), Error> {
        let mut msg = MsgBuf::borrow_def();
        msg.set(kif::tilemux::RemoveQuotas {
            op: kif::tilemux::Sidecalls::REMOVE_QUOTAS.val as u64,
            time: kif::OptionalValue::new(time),
            pts: kif::OptionalValue::new(pts),
        });

        Self::send_receive_sidecall_async::<kif::tilemux::RemoveQuotas>(tilemux, None, msg)
            .map(|_| ())
    }

    pub fn map_async(
        tilemux: RefMut<'_, Self>,
        act: ActId,
        virt: goff,
        glob: GlobAddr,
        pages: usize,
        perm: kif::PageFlags,
    ) -> Result<(), Error> {
        let mut msg = MsgBuf::borrow_def();
        msg.set(kif::tilemux::Map {
            op: kif::tilemux::Sidecalls::MAP.val as u64,
            act_sel: act as u64,
            virt: virt as u64,
            global: glob.raw(),
            pages: pages as u64,
            perm: perm.bits() as u64,
        });

        Self::send_receive_sidecall_async::<kif::tilemux::Map>(tilemux, Some(act), msg).map(|_| ())
    }

    pub fn unmap_async(
        tilemux: RefMut<'_, Self>,
        act: ActId,
        virt: goff,
        pages: usize,
    ) -> Result<(), Error> {
        Self::map_async(
            tilemux,
            act,
            virt,
            GlobAddr::new(0),
            pages,
            kif::PageFlags::empty(),
        )
    }

    pub fn translate_async(
        tilemux: RefMut<'_, Self>,
        act: ActId,
        virt: goff,
        perm: kif::Perm,
    ) -> Result<GlobAddr, Error> {
        use base::cfg::PAGE_MASK;

        let mut msg = MsgBuf::borrow_def();
        msg.set(kif::tilemux::Translate {
            op: kif::tilemux::Sidecalls::TRANSLATE.val as u64,
            act_sel: act as u64,
            virt: virt as u64,
            perm: perm.bits() as u64,
        });

        Self::send_receive_sidecall_async::<kif::tilemux::Translate>(tilemux, Some(act), msg)
            .map(|reply| GlobAddr::new(reply.val1 & !(PAGE_MASK as goff)))
    }

    pub fn notify_invalidate(&mut self, act: ActId, ep: EpId) -> Result<(), Error> {
        let mut msg = MsgBuf::borrow_def();
        msg.set(kif::tilemux::EpInval {
            op: kif::tilemux::Sidecalls::EP_INVAL.val as u64,
            act_sel: act as u64,
            ep: ep as u64,
        });

        self.send_sidecall::<kif::tilemux::EpInval>(Some(act), &msg)
            .map(|_| ())
    }

    fn send_sidecall<R: core::fmt::Debug>(
        &mut self,
        act: Option<ActId>,
        req: &MsgBuf,
    ) -> Result<thread::Event, Error> {
        use crate::tiles::{ActivityMng, State};

        // if the activity has no app anymore, don't send the notify
        if let Some(id) = act {
            if !ActivityMng::activity(id)
                .map(|v| v.state() != State::DEAD)
                .unwrap_or(false)
            {
                return Err(Error::new(Code::ActivityGone));
            }
        }

        klog!(
            TMC,
            "TileMux[{}] sending {:?}",
            self.tile_id(),
            req.get::<R>()
        );

        self.queue.send(tcu::TMSIDE_REP, 0, req)
    }

    fn send_receive_sidecall_async<R: core::fmt::Debug>(
        mut tilemux: RefMut<'_, Self>,
        act: Option<ActId>,
        req: base::mem::MsgBufRef<'_>,
    ) -> Result<&'static kif::tilemux::Response, Error> {
        use crate::com::SendQueue;

        let event = tilemux.send_sidecall::<R>(act, &req)?;
        drop(req);
        drop(tilemux);

        let reply = SendQueue::receive_async(event)?;

        let reply = reply.get_data::<kif::tilemux::Response>();
        if reply.error == 0 {
            Ok(reply)
        }
        else {
            Err(Error::new(Code::from(reply.error as u32)))
        }
    }
}

#[cfg(target_vendor = "host")]
impl TileMux {
    pub fn update_eps(&mut self) -> Result<(), Error> {
        ktcu::update_eps(self.tile_id())
    }

    pub fn activity_init_async(
        _tilemux: RefMut<'_, Self>,
        _act: ActId,
        _time_quota: quota::Id,
        _pt_quota: quota::Id,
        _eps_start: EpId,
    ) -> Result<(), Error> {
        Ok(())
    }

    pub fn activity_ctrl_async(
        _tilemux: RefMut<'_, Self>,
        _act: ActId,
        _ctrl: base::kif::tilemux::ActivityOp,
    ) -> Result<(), Error> {
        Ok(())
    }

    pub fn derive_quota_async(
        _tilemux: RefMut<'_, Self>,
        _parent_time: quota::Id,
        _parent_pts: quota::Id,
        _time: Option<u64>,
        _pts: Option<u64>,
    ) -> Result<(quota::Id, quota::Id), Error> {
        Ok((0, 0))
    }

    pub fn get_quota_async(
        _tilemux: RefMut<'_, Self>,
        _time: quota::Id,
        _pts: quota::Id,
    ) -> Result<(quota::Quota<u64>, quota::Quota<usize>), Error> {
        Ok((quota::Quota::default(), quota::Quota::default()))
    }

    pub fn set_quota_async(
        _tilemux: RefMut<'_, Self>,
        _id: quota::Id,
        _time: u64,
        _pts: u64,
    ) -> Result<(), Error> {
        Ok(())
    }

    pub fn remove_quotas_async(
        _tilemux: RefMut<'_, Self>,
        _time: Option<quota::Id>,
        _pts: Option<quota::Id>,
    ) -> Result<(), Error> {
        Ok(())
    }

    pub fn map_async(
        _tilemux: RefMut<'_, Self>,
        _act: ActId,
        _virt: goff,
        _glob: GlobAddr,
        _pages: usize,
        _perm: kif::PageFlags,
    ) -> Result<(), Error> {
        Ok(())
    }

    pub fn unmap_async(
        _tilemux: RefMut<'_, Self>,
        _act: ActId,
        _virt: goff,
        _pages: usize,
    ) -> Result<(), Error> {
        Ok(())
    }

    pub fn notify_invalidate(&mut self, _act: ActId, _ep: EpId) -> Result<(), Error> {
        Ok(())
    }

    fn send_sidecall<R: core::fmt::Debug>(
        &mut self,
        _act: Option<ActId>,
        _req: &MsgBuf,
    ) -> Result<thread::Event, Error> {
        Err(Error::new(Code::NotSup))
    }
}
