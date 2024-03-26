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
use base::cell::RefMut;
use base::cfg;
use base::col::{BitArray, Vec};
use base::env;
use base::errors::{Code, Error};
use base::io::LogFlags;
use base::kif;
use base::log;
use base::mem::{size_of, GlobAddr, GlobOff, MsgBuf, VirtAddr};
use base::quota;
use base::rc::{Rc, SRc, Weak};
use base::tcu::{self, ActId, EpId, TileId};

use core::cmp;

use crate::cap::{
    EPCategory, EPObject, EPQuota, GateObject, MGateObject, RGateObject, SGateObject, TileObject,
};
use crate::ktcu;
use crate::mem;
use crate::platform;
use crate::tiles::{tilemng, INVAL_ID};

struct TileState {
    pmp: Vec<Rc<EPObject>>,
    eps_region: Option<mem::Allocation>,
    eps: BitArray,
}

impl TileState {
    fn new(tile: &SRc<TileObject>, ep_count: Option<usize>) -> Result<Self, Error> {
        // create PMP EPObjects for this Tile
        let mut pmp = Vec::new();
        for ep in 0..tcu::PMEM_PROT_EPS as EpId {
            pmp.push(EPObject::new(EPCategory::PMP, Weak::new(), ep, 0, tile));
        }

        assert!(platform::tile_desc(tile.tile()).has_internal_eps() == ep_count.is_none());
        let (num, eps_region) = match ep_count {
            Some(count) => {
                // more EPs are not supported as we only have 16-bit for EP ids
                if count < tcu::FIRST_USER_EP as usize || count >= tcu::INVALID_EP as usize {
                    return Err(Error::new(Code::InvArgs));
                }

                let ep_reg_size = count * (tcu::EP_REGS * size_of::<tcu::Reg>());
                let region =
                    mem::borrow_mut().allocate(mem::MemType::EPS, ep_reg_size as GlobOff, 1)?;
                ktcu::set_eps_region(tile.tile(), region.global(), region.size())?;
                (count, Some(region))
            },
            None => (ktcu::get_ep_count(tile.tile())?, None),
        };

        tile.reset(num);

        let mut state = TileState {
            pmp,
            eps_region,
            eps: BitArray::new(num),
        };

        // first EP is reserved for TileMux's memory region
        state.eps.set(0);
        for ep in tcu::PMEM_PROT_EPS as EpId..tcu::FIRST_USER_EP {
            state.eps.set(ep as usize);
        }

        Ok(state)
    }

    fn find_eps(&self, count: usize) -> Result<EpId, Error> {
        // the PMP EPs cannot be allocated
        let mut start = cmp::max(tcu::FIRST_USER_EP as usize, self.eps.first_clear());
        let mut bit = start;
        while bit < start + count as usize && bit < self.eps.size() {
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

    fn eps_free(&self, start: EpId, count: usize) -> bool {
        for ep in start..start + count as EpId {
            if self.eps.is_set(ep as usize) {
                return false;
            }
        }
        true
    }

    fn alloc_eps(&mut self, start: EpId, count: usize) {
        for bit in start..start + count as EpId {
            assert!(!self.eps.is_set(bit as usize));
            self.eps.set(bit as usize);
        }
    }

    fn free_eps(&mut self, start: EpId, count: usize) {
        for bit in start..start + count as EpId {
            assert!(self.eps.is_set(bit as usize));
            self.eps.clear(bit as usize);
        }
    }
}

impl Drop for TileState {
    fn drop(&mut self) {
        if let Some(region) = self.eps_region {
            mem::borrow_mut().free(&region);
        }
    }
}

pub struct TileMux {
    tile: SRc<TileObject>,
    acts: Vec<ActId>,
    queue: base::boxed::Box<crate::com::SendQueue>,
    state: Option<TileState>,
    mux_type: kif::syscalls::MuxType,
    shutdown: bool,
}

impl TileMux {
    pub fn new(tile_id: TileId) -> Self {
        let tile = TileObject::new(
            tile_id,
            // empty quota until reset
            EPQuota::new(0),
            kif::tilemux::DEF_QUOTA_ID,
            kif::tilemux::DEF_QUOTA_ID,
            false,
        );

        TileMux {
            tile,
            acts: Vec::new(),
            queue: crate::com::SendQueue::new(crate::com::QueueId::TileMux(tile_id), tile_id),
            state: None,
            mux_type: kif::syscalls::MuxType::None,
            shutdown: false,
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.state.is_some() && !self.shutdown
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

    fn init_state(&mut self, ep_count: Option<usize>) {
        assert!(self.state.is_none());
        self.state = Some(TileState::new(&self.tile, ep_count).unwrap());

        if platform::tile_desc(self.tile_id()).supports_tilemux() {
            // configure send EP
            ktcu::config_remote_ep(self.tile_id(), tcu::KPEX_SEP, |regs, tgtep| {
                ktcu::config_send(
                    regs,
                    tgtep,
                    kif::tilemux::ACT_ID as ActId,
                    self.tile_id().raw() as tcu::Label,
                    platform::kernel_tile(),
                    ktcu::KPEX_EP,
                    cfg::KPEX_RBUF_ORD,
                    1,
                );
            })
            .unwrap();

            // configure receive EP
            let mut rbuf = cfg::TILEMUX_RBUF_SPACE.as_phys();
            ktcu::config_remote_ep(self.tile_id(), tcu::KPEX_REP, |regs, tgtep| {
                ktcu::config_recv(
                    regs,
                    tgtep,
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
            ktcu::config_remote_ep(self.tile_id(), tcu::TMSIDE_REP, |regs, tgtep| {
                ktcu::config_recv(
                    regs,
                    tgtep,
                    kif::tilemux::ACT_ID as ActId,
                    rbuf,
                    cfg::TMUP_RBUF_ORD,
                    cfg::TMUP_RBUF_ORD,
                    Some(tcu::TMSIDE_RPLEP),
                );
            })
            .unwrap();
        }
    }

    fn deinit_state(&mut self) {
        // now that the tile is stopped, deconfigure PMP EPs
        for ep in 0..tcu::PMEM_PROT_EPS as tcu::EpId {
            // cannot fail for memory EPs
            let ep_obj = self.pmp_ep(ep).unwrap();
            ep_obj.deconfigure(false).unwrap();
        }

        self.state = None;
        self.mux_type = kif::syscalls::MuxType::None;
    }

    pub fn reset_async(
        tile: TileId,
        mux_mem: Option<GateObject>,
        ep_count: Option<usize>,
        root: bool,
    ) -> Result<(), Error> {
        let start = mux_mem.is_some();

        if tilemng::tilemux(tile).has_activities() {
            return Err(Error::new(Code::InvState));
        }

        log!(
            LogFlags::KernTiles,
            "Resetting tile {} (start={})",
            tile,
            start
        );

        {
            let mut tilemux = tilemng::tilemux(tile);
            // reset can only be used in two ways: off -> on and on -> off
            if (!tilemux.is_initialized() && !start) || (tilemux.is_initialized() && start) {
                return Err(Error::new(Code::InvArgs));
            }

            // should we start and therefore initialize the tile?
            if let (Some(mux_mem), ep_count) = (mux_mem, ep_count) {
                tilemux.init_state(ep_count);
                tilemux.shutdown = false;

                let mgate = match mux_mem {
                    GateObject::Mem(ref mg) => mg.clone(),
                    _ => unreachable!(),
                };

                // use the given memory gate for the first PMP EP (for the multiplexer)
                if platform::tile_desc(tile).has_virtmem() {
                    tilemux.configure_pmp_ep(0, mux_mem)?;
                }

                if env::boot().platform == env::Platform::Hw {
                    // write trampoline to 0x1000_0000 to jump to TileMux's entry point
                    let trampoline: u64 = 0x0000_0000_0000_306f; // j _start (+0x3000)
                    ktcu::write_slice(mgate.tile_id(), mgate.offset(), &[trampoline]);
                }
            }
            else {
                // to ensure that we don't send more requests to this tilemux instance (e.g., in
                // other kernel threads), we mark it as shutdown and therefore not available.
                tilemux.shutdown = true;
                // give tilemux the chance to shutdown properly
                if platform::tile_desc(tile).is_programmable() {
                    Self::shutdown_async(tilemux).unwrap();
                }
            }
        }

        // reset the tile; start it if mux_mem is some; stop it otherwise
        ktcu::reset_tile(tile, start)?;

        let mut tilemux = tilemng::tilemux(tile);
        if start {
            // for root, it has to be TileMux and we don't support async calls yet, because there
            // are no other threads yet to switch to.
            if root {
                tilemux.mux_type = kif::syscalls::MuxType::TileMux;
            }
            else if !platform::tile_desc(tile).supports_tilemux() {
                tilemux.mux_type = kif::syscalls::MuxType::None;
            }
            else {
                tilemng::tilemux(tile).mux_type = Self::info_async(tilemux)?;
            }
        }
        else {
            tilemux.deinit_state();
        }

        Ok(())
    }

    pub fn tile(&self) -> &SRc<TileObject> {
        &self.tile
    }

    pub fn tile_id(&self) -> TileId {
        self.tile.tile()
    }

    pub fn mux_type(&self) -> kif::syscalls::MuxType {
        self.mux_type
    }

    pub fn ep_count(&self) -> Option<usize> {
        self.state.as_ref().map(|state| state.eps.size())
    }

    pub fn pmp_ep(&self, ep: EpId) -> Option<&Rc<EPObject>> {
        self.state.as_ref().map(|state| &state.pmp[ep as usize])
    }

    pub fn configure_pmp_ep(&mut self, ep: tcu::EpId, gate: GateObject) -> Result<(), Error> {
        match gate {
            GateObject::Mem(ref mg) => {
                self.config_mem_ep(ep, INVAL_ID, mg, mg.tile_id())?;

                // remember that the MemGate is activated on this EP for the case that the MemGate gets
                // revoked. If so, the EP is automatically invalidated.
                let ep_obj = self.pmp_ep(ep).ok_or_else(|| Error::new(Code::InvState))?;
                EPObject::configure_obj(ep_obj, gate);
            },
            _ => return Err(Error::new(Code::InvArgs)),
        }
        Ok(())
    }

    pub fn find_eps(&self, count: usize) -> Result<EpId, Error> {
        self.state
            .as_ref()
            .ok_or_else(|| Error::new(Code::InvState))?
            .find_eps(count)
    }

    pub fn eps_free(&self, start: EpId, count: usize) -> bool {
        self.state
            .as_ref()
            .map(|state| state.eps_free(start, count))
            .unwrap_or(false)
    }

    pub fn alloc_eps(&mut self, start: EpId, count: usize) {
        let tile_id = self.tile_id();
        if let Some(state) = self.state.as_mut() {
            log!(
                LogFlags::KernEPs,
                "TileMux[{}] allocating EPS {}..{}",
                tile_id,
                start,
                start as usize + count - 1
            );
            state.alloc_eps(start, count);
        }
    }

    pub fn free_eps(&mut self, start: EpId, count: usize) {
        let tile_id = self.tile_id();
        if let Some(state) = self.state.as_mut() {
            log!(
                LogFlags::KernEPs,
                "TileMux[{}] freeing EPS {}..{}",
                tile_id,
                start,
                start as usize + count - 1
            );
            state.free_eps(start, count);
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

        ktcu::config_remote_ep(self.tile_id(), ep, |regs, tgtep| {
            let act = self.ep_activity_id(act);
            let (rpe, rep) = rgate.location().unwrap();
            ktcu::config_send(
                regs,
                tgtep,
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
        ktcu::config_remote_ep(self.tile_id(), ep, |regs, tgtep| {
            let act = self.ep_activity_id(act);
            ktcu::config_recv(
                regs,
                tgtep,
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
        ktcu::config_remote_ep(self.tile_id(), ep, |regs, tgtep| {
            let act = self.ep_activity_id(act);
            ktcu::config_mem(
                regs,
                tgtep,
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
        let unread_mask = ktcu::invalidate_ep_remote(self.tile_id(), ep, force)?;
        if unread_mask != 0 && notify && platform::tile_desc(self.tile_id()).supports_tilemux() {
            let mut buf = MsgBuf::borrow_def();
            let msg = kif::tilemux::RemMsgs {
                act_id: act as u64,
                unread_mask,
            };
            build_vmsg!(buf, kif::tilemux::Sidecalls::RemMsgs, &msg);

            self.send_sidecall::<kif::tilemux::RemMsgs>(Some(act), &buf, &msg, true)
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
        ktcu::inv_reply_remote(recv_tile, recv_ep, self.tile_id(), send_ep)
    }

    pub fn reset_stats(&mut self) -> Result<(), Error> {
        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::ResetStats {};
        build_vmsg!(buf, kif::tilemux::Sidecalls::ResetStats, &msg);

        self.send_sidecall::<kif::tilemux::ResetStats>(None, &buf, &msg, true)
            .map(|_| ())
    }

    pub fn shutdown_async(tilemux: RefMut<'_, Self>) -> Result<(), Error> {
        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::Shutdown {};
        build_vmsg!(buf, kif::tilemux::Sidecalls::Shutdown, &msg);

        // don't check here whether tilemux is still initialized, as it needs to be marked as
        // deinitialized before suspending the thread and we always know that it's initialized when
        // using this sidecall.
        Self::send_receive_sidecall_async::<kif::tilemux::Shutdown>(tilemux, None, buf, &msg, false)
            .map(|_| ())
    }

    pub fn handle_call_async(tilemux: RefMut<'_, Self>, msg: &tcu::Message) {
        use base::serialize::M3Deserializer;

        let mut de = M3Deserializer::new(msg.as_words());
        let op: kif::tilemux::Calls = de.pop().unwrap();

        match op {
            kif::tilemux::Calls::Exit => Self::handle_exit_async(tilemux, msg, &mut de).unwrap(),
        }
    }

    fn handle_exit_async(
        tilemux: RefMut<'_, Self>,
        msg: &tcu::Message,
        de: &mut base::serialize::M3Deserializer<'_>,
    ) -> Result<(), Error> {
        use crate::tiles::ActivityMng;

        let r: kif::tilemux::Exit = de.pop()?;

        let tile_id = tilemux.tile_id();
        log!(LogFlags::KernTMC, "TileMux[{}] received {:?}", tile_id, r);

        let has_act = tilemux.acts.contains(&r.act_id);
        drop(tilemux);

        if has_act {
            let act = ActivityMng::activity(r.act_id).unwrap();
            act.stop_app_async(r.status, true, INVAL_ID);
        }

        let mut reply = MsgBuf::borrow_def();
        reply.set(kif::DefaultReply {
            error: Code::Success,
        });
        if let Err(e) = ktcu::reply(ktcu::KPEX_EP, &reply, msg) {
            log!(
                LogFlags::Error,
                "TileMux[{}] got {} on Exit sidecall reply",
                tile_id,
                e
            );
        }

        Ok(())
    }

    fn info_async(tilemux: RefMut<'_, Self>) -> Result<kif::syscalls::MuxType, Error> {
        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::Info {};
        build_vmsg!(buf, kif::tilemux::Sidecalls::Info, &msg);

        Self::send_receive_sidecall_async::<kif::tilemux::Info>(tilemux, None, buf, &msg, true)
            .map(|r| kif::syscalls::MuxType::try_from(r.val1).unwrap())
    }

    pub fn activity_init_async(
        tilemux: RefMut<'_, Self>,
        act: ActId,
        time_quota: quota::Id,
        pt_quota: quota::Id,
        eps_start: EpId,
    ) -> Result<(), Error> {
        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::ActInit {
            act_id: act as u64,
            time_quota,
            pt_quota,
            eps_start,
        };
        build_vmsg!(buf, kif::tilemux::Sidecalls::ActInit, &msg);

        Self::send_receive_sidecall_async::<kif::tilemux::ActInit>(tilemux, None, buf, &msg, true)
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
        build_vmsg!(buf, kif::tilemux::Sidecalls::ActCtrl, &msg);

        Self::send_receive_sidecall_async::<kif::tilemux::ActivityCtrl>(
            tilemux, None, buf, &msg, true,
        )
        .map(|_| ())
    }

    pub fn request_ep_async(
        tilemux: RefMut<'_, Self>,
        act: ActId,
        ep_id: EpId,
        replies: usize,
    ) -> Result<EpId, Error> {
        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::ReqEP {
            act_id: act as u64,
            ep_id,
            replies,
        };
        build_vmsg!(buf, kif::tilemux::Sidecalls::ReqEP, &msg);

        Self::send_receive_sidecall_async::<kif::tilemux::ReqEP>(tilemux, None, buf, &msg, true)
            .map(|r| r.val1 as EpId)
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
        build_vmsg!(buf, kif::tilemux::Sidecalls::DeriveQuota, &msg);

        Self::send_receive_sidecall_async::<kif::tilemux::DeriveQuota>(
            tilemux, None, buf, &msg, true,
        )
        .map(|r| (r.val1 as quota::Id, r.val2 as quota::Id))
    }

    pub fn get_quota_async(
        tilemux: RefMut<'_, Self>,
        time: quota::Id,
        pts: quota::Id,
    ) -> Result<(quota::Quota<u64>, quota::Quota<usize>), Error> {
        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::GetQuota { time, pts };
        build_vmsg!(buf, kif::tilemux::Sidecalls::GetQuota, &msg);

        let tile_id = (tilemux.tile_id().raw() as quota::Id) << 8;
        Self::send_receive_sidecall_async::<kif::tilemux::GetQuota>(tilemux, None, buf, &msg, true)
            .map(|r| {
                (
                    quota::Quota::new(tile_id | time, r.val1 >> 32, r.val1 & 0xFFFF_FFFF),
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
        pts: usize,
    ) -> Result<(), Error> {
        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::SetQuota { id, time, pts };
        build_vmsg!(buf, kif::tilemux::Sidecalls::SetQuota, &msg);

        Self::send_receive_sidecall_async::<kif::tilemux::SetQuota>(tilemux, None, buf, &msg, true)
            .map(|_| ())
    }

    pub fn remove_quotas_async(
        tilemux: RefMut<'_, Self>,
        time: Option<quota::Id>,
        pts: Option<quota::Id>,
    ) -> Result<(), Error> {
        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::RemoveQuotas { time, pts };
        build_vmsg!(buf, kif::tilemux::Sidecalls::RemoveQuotas, &msg);

        Self::send_receive_sidecall_async::<kif::tilemux::RemoveQuotas>(
            tilemux, None, buf, &msg, true,
        )
        .map(|_| ())
    }

    pub fn map_async(
        tilemux: RefMut<'_, Self>,
        act: ActId,
        virt: VirtAddr,
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
        build_vmsg!(buf, kif::tilemux::Sidecalls::Map, &msg);

        Self::send_receive_sidecall_async::<kif::tilemux::Map>(tilemux, Some(act), buf, &msg, true)
            .map(|_| ())
    }

    pub fn unmap_async(
        tilemux: RefMut<'_, Self>,
        act: ActId,
        virt: VirtAddr,
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
        virt: VirtAddr,
        perm: kif::PageFlags,
    ) -> Result<GlobAddr, Error> {
        use base::cfg::PAGE_MASK;

        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::Translate {
            act_id: act as u64,
            virt,
            perm,
        };
        build_vmsg!(buf, kif::tilemux::Sidecalls::Translate, msg);

        Self::send_receive_sidecall_async::<kif::tilemux::Translate>(
            tilemux,
            Some(act),
            buf,
            &msg,
            true,
        )
        .map(|reply| GlobAddr::new(reply.val1 & !(PAGE_MASK as GlobOff)))
    }

    pub fn notify_invalidate(&mut self, act: ActId, ep: EpId) -> Result<(), Error> {
        let mut buf = MsgBuf::borrow_def();
        let msg = kif::tilemux::EpInval {
            act_id: act as u64,
            ep,
        };
        build_vmsg!(buf, kif::tilemux::Sidecalls::EPInval, msg);

        self.send_sidecall::<kif::tilemux::EpInval>(Some(act), &buf, &msg, true)
            .map(|_| ())
    }

    fn send_sidecall<R: core::fmt::Debug>(
        &mut self,
        act: Option<ActId>,
        req: &MsgBuf,
        msg: &R,
        check_init: bool,
    ) -> Result<thread::Event, Error> {
        use crate::tiles::{ActivityMng, State};

        // if tilemux is not initialized, we cannot talk to it
        if check_init && !self.is_initialized() {
            return Err(Error::new(Code::RecvGone));
        }

        // if the activity has no app anymore, don't send the notify
        if let Some(id) = act {
            if !ActivityMng::activity(id)
                .map(|v| v.state() != State::DEAD)
                .unwrap_or(false)
            {
                return Err(Error::new(Code::ActivityGone));
            }
        }

        log!(
            LogFlags::KernTMC,
            "TileMux[{}] sending {:?}",
            self.tile_id(),
            msg
        );

        self.queue.send(tcu::TMSIDE_REP, 0, req)
    }

    fn send_receive_sidecall_async<R: core::fmt::Debug>(
        mut tilemux: RefMut<'_, Self>,
        act: Option<ActId>,
        req: base::mem::MsgBufRef<'_>,
        msg: &R,
        check_init: bool,
    ) -> Result<kif::tilemux::Response, Error> {
        use crate::com::SendQueue;

        let tile_id = tilemux.tile_id();
        let event = tilemux.send_sidecall::<R>(act, &req, msg, check_init)?;
        drop(req);
        drop(tilemux);

        let reply = SendQueue::receive_async(event)?;

        let mut de = base::serialize::M3Deserializer::new(reply.as_words());
        let code: Code = de.pop()?;

        log!(
            LogFlags::KernTMC,
            "TileMux[{}] received {:?}",
            tile_id,
            code
        );

        if code == Code::Success {
            de.pop()
        }
        else {
            Err(Error::new(code))
        }
    }
}
