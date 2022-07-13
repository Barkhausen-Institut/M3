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
use base::cell::{RefCell, RefMut};
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

use crate::cap::{BWQuota, EPObject, EPQuota, MGateObject, RGateObject, SGateObject, TileObject};
use crate::ktcu;
use crate::platform;
use crate::tiles::INVAL_ID;

pub struct TileMux {
    tile: SRc<TileObject>,
    acts: Vec<ActId>,
    queue: base::boxed::Box<crate::com::SendQueue>,
    pmp: Vec<Rc<EPObject>>,
    eps: BitVec,
}

impl TileMux {
    pub fn new(tile: TileId) -> Self {
        let tile_obj = TileObject::new(
            tile,
            EPQuota::new((tcu::AVAIL_EPS - tcu::FIRST_USER_EP) as u32),
            BWQuota::new(
                kif::tilemux::IDLE_QUOTA_ID,
                Rc::new(RefCell::new(kif::tilemux::IDLE_QUOTA_ID + 1)),
                tcu::MEM_BW_UNLIMITED,
            ),
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
            queue: crate::com::SendQueue::new(crate::com::QueueId::TileMux(tile), tile),
            pmp,
            eps: BitVec::new(tcu::AVAIL_EPS as usize),
        };

        tilemux.eps.set(0); // first EP is reserved for TileMux's memory region

        for ep in tcu::PMEM_PROT_EPS as EpId..tcu::FIRST_USER_EP {
            tilemux.eps.set(ep as usize);
        }

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
        let mut rbuf = cfg::TILEMUX_RBUF_SPACE as goff;
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

        let unread_mask = ktcu::invalidate_ep_remote(self.tile_id(), ep, force)?;
        if unread_mask != 0 && notify {
            let mut buf = MsgBuf::borrow_def();
            let msg = kif::tilemux::RemMsgs {
                act_id: act as u64,
                unread_mask,
            };
            build_vmsg!(buf, kif::tilemux::Sidecalls::REM_MSGS, &msg);

            self.send_sidecall::<kif::tilemux::RemMsgs>(Some(act), &buf, &msg)
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
        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::ResetStats {};
        build_vmsg!(buf, kif::tilemux::Sidecalls::RESET_STATS, &msg);

        self.send_sidecall::<kif::tilemux::ResetStats>(None, &buf, &msg)
            .map(|_| ())
    }

    pub fn shutdown(&mut self) -> Result<(), Error> {
        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::Shutdown {};
        build_vmsg!(buf, kif::tilemux::Sidecalls::SHUTDOWN, &msg);

        self.send_sidecall::<kif::tilemux::Shutdown>(None, &buf, &msg)
            .map(|_| ())
    }

    pub fn handle_call_async(tilemux: RefMut<'_, Self>, msg: &tcu::Message) {
        use base::serialize::M3Deserializer;

        let mut de = M3Deserializer::new(msg.as_words());
        let op: kif::tilemux::Calls = de.pop().unwrap();

        let res = match op {
            kif::tilemux::Calls::EXIT => Self::handle_exit_async(tilemux, &mut de),
            _ => {
                klog!(ERR, "Unexpected call from TileMux: {}", op);
                Err(Error::new(Code::InvArgs))
            },
        };

        let mut reply = MsgBuf::borrow_def();
        build_vmsg!(reply, kif::DefaultReply {
            error: res.err().map(|e| e.code()).unwrap_or(Code::None)
        });
        ktcu::reply(ktcu::KPEX_EP, &reply, msg).unwrap();
    }

    fn handle_exit_async(
        tilemux: RefMut<'_, Self>,
        de: &mut base::serialize::M3Deserializer<'_>,
    ) -> Result<(), Error> {
        use crate::tiles::ActivityMng;

        let r: kif::tilemux::Exit = de.pop()?;

        klog!(TMC, "TileMux[{}] received {:?}", tilemux.tile_id(), r);

        let has_act = tilemux.acts.contains(&r.act_id);
        drop(tilemux);

        if has_act {
            let act = ActivityMng::activity(r.act_id).unwrap();
            act.stop_app_async(r.status, true);
        }
        Ok(())
    }

    pub fn activity_init_async(
        tilemux: RefMut<'_, Self>,
        act: ActId,
        bw_quota: quota::Id,
        time_quota: quota::Id,
        pt_quota: quota::Id,
        eps_start: EpId,
    ) -> Result<(), Error> {
        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::ActInit {
            act_id: act as u64,
            bw_quota,
            time_quota,
            pt_quota,
            eps_start,
        };
        build_vmsg!(buf, kif::tilemux::Sidecalls::ACT_INIT, &msg);

        Self::send_receive_sidecall_async::<kif::tilemux::ActInit>(tilemux, None, buf, &msg)
            .map(|_| ())
    }

    pub fn activity_ctrl_async(
        tilemux: RefMut<'_, Self>,
        act: ActId,
        act_op: base::kif::tilemux::ActivityOp,
    ) -> Result<(), Error> {
        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::ActivityCtrl {
            act_id: act as u64,
            act_op,
        };
        build_vmsg!(buf, kif::tilemux::Sidecalls::ACT_CTRL, &msg);

        Self::send_receive_sidecall_async::<kif::tilemux::ActivityCtrl>(tilemux, None, buf, &msg)
            .map(|_| ())
    }

    pub fn derive_quota_async(
        tilemux: RefMut<'_, Self>,
        parent_time: quota::Id,
        parent_pts: quota::Id,
        time: Option<u64>,
        pts: Option<usize>,
    ) -> Result<(quota::Id, quota::Id), Error> {
        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::DeriveQuota {
            parent_time,
            parent_pts,
            time,
            pts,
        };
        build_vmsg!(buf, kif::tilemux::Sidecalls::DERIVE_QUOTA, &msg);

        Self::send_receive_sidecall_async::<kif::tilemux::DeriveQuota>(tilemux, None, buf, &msg)
            .map(|r| (r.val1 as quota::Id, r.val2 as quota::Id))
    }

    pub fn get_quota_async(
        tilemux: RefMut<'_, Self>,
        time: quota::Id,
        pts: quota::Id,
    ) -> Result<(quota::Quota<u64>, quota::Quota<usize>), Error> {
        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::GetQuota { time, pts };
        build_vmsg!(buf, kif::tilemux::Sidecalls::GET_QUOTA, &msg);

        let tile_id = (tilemux.tile.tile() as quota::Id) << 8;
        Self::send_receive_sidecall_async::<kif::tilemux::GetQuota>(tilemux, None, buf, &msg).map(
            |r| {
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
            },
        )
    }

    pub fn set_quota_async(
        tilemux: RefMut<'_, Self>,
        id: quota::Id,
        time: u64,
        pts: usize,
    ) -> Result<(), Error> {
        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::SetQuota { id, time, pts };
        build_vmsg!(buf, kif::tilemux::Sidecalls::SET_QUOTA, &msg);

        Self::send_receive_sidecall_async::<kif::tilemux::SetQuota>(tilemux, None, buf, &msg)
            .map(|_| ())
    }

    pub fn remove_quotas_async(
        tilemux: RefMut<'_, Self>,
        time: Option<quota::Id>,
        pts: Option<quota::Id>,
    ) -> Result<(), Error> {
        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::RemoveQuotas { time, pts };
        build_vmsg!(buf, kif::tilemux::Sidecalls::REMOVE_QUOTAS, &msg);

        Self::send_receive_sidecall_async::<kif::tilemux::RemoveQuotas>(tilemux, None, buf, &msg)
            .map(|_| ())
    }

    pub fn map_async(
        tilemux: RefMut<'_, Self>,
        act: ActId,
        virt: goff,
        global: GlobAddr,
        pages: usize,
        perm: kif::PageFlags,
    ) -> Result<(), Error> {
        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::Map {
            act_id: act as u64,
            virt,
            global,
            pages,
            perm,
        };
        build_vmsg!(buf, kif::tilemux::Sidecalls::MAP, &msg);

        Self::send_receive_sidecall_async::<kif::tilemux::Map>(tilemux, Some(act), buf, &msg)
            .map(|_| ())
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
        perm: kif::PageFlags,
    ) -> Result<GlobAddr, Error> {
        use base::cfg::PAGE_MASK;

        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::Translate {
            act_id: act as u64,
            virt,
            perm,
        };
        build_vmsg!(buf, kif::tilemux::Sidecalls::TRANSLATE, msg);

        Self::send_receive_sidecall_async::<kif::tilemux::Translate>(tilemux, Some(act), buf, &msg)
            .map(|reply| GlobAddr::new(reply.val1 & !(PAGE_MASK as goff)))
    }

    pub fn notify_invalidate(&mut self, act: ActId, ep: EpId) -> Result<(), Error> {
        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::EpInval {
            act_id: act as u64,
            ep,
        };
        build_vmsg!(buf, kif::tilemux::Sidecalls::EP_INVAL, msg);

        self.send_sidecall::<kif::tilemux::EpInval>(Some(act), &buf, &msg)
            .map(|_| ())
    }

    fn send_sidecall<R: core::fmt::Debug>(
        &mut self,
        act: Option<ActId>,
        req: &MsgBuf,
        msg: &R,
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

        klog!(TMC, "TileMux[{}] sending {:?}", self.tile_id(), msg);

        self.queue.send(tcu::TMSIDE_REP, 0, req)
    }

    fn send_receive_sidecall_async<R: core::fmt::Debug>(
        mut tilemux: RefMut<'_, Self>,
        act: Option<ActId>,
        req: base::mem::MsgBufRef<'_>,
        msg: &R,
    ) -> Result<kif::tilemux::Response, Error> {
        use crate::com::SendQueue;

        let event = tilemux.send_sidecall::<R>(act, &req, msg)?;
        drop(req);
        drop(tilemux);

        let reply = SendQueue::receive_async(event)?;

        let mut de = base::serialize::M3Deserializer::new(reply.as_words());
        let code: Code = de.pop()?;
        if code == Code::None {
            de.pop()
        }
        else {
            Err(Error::new(code))
        }
    }
}
