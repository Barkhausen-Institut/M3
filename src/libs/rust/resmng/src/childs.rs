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

use bitflags::bitflags;
use core::fmt;
use m3::boxed::Box;
use m3::cap::Selector;
use m3::cell::{Cell, RefCell, RefMut, StaticRefCell};
use m3::col::{String, ToString, Treap, Vec};
use m3::com::{MemGate, RecvGate, SGateArgs, SendGate};
use m3::env;
use m3::errors::{Code, Error};
use m3::format;
use m3::goff;
use m3::kif::{self, CapRngDesc, CapType, Perm};
use m3::log;
use m3::math;
use m3::mem::MsgBuf;
use m3::println;
use m3::quota::{Id as QuotaId, Quota};
use m3::rc::Rc;
use m3::session::{ResMngActInfo, ResMngActInfoResult};
use m3::syscalls;
use m3::tcu;
use m3::tiles::{
    Activity, ChildActivity, KMem, Mapper, RunningActivity, RunningProgramActivity, TileQuota,
};
use m3::vfs::{File, FileRef};

use crate::config::AppConfig;
use crate::gates;
use crate::memory::{self, Allocation, MemPool};
use crate::sems;
use crate::services::{self, Session};
use crate::subsys::SubsystemBuilder;
use crate::tiles;
use crate::{events, subsys};

pub type Id = u32;

pub struct ChildMem {
    id: Id,
    pool: Rc<RefCell<MemPool>>,
    total: goff,
    quota: Cell<goff>,
}

impl ChildMem {
    pub fn new(id: Id, pool: Rc<RefCell<MemPool>>, quota: goff) -> Rc<Self> {
        Rc::new(Self {
            id,
            pool,
            total: quota,
            quota: Cell::new(quota),
        })
    }

    pub fn pool(&self) -> &Rc<RefCell<MemPool>> {
        &self.pool
    }

    pub(crate) fn quota(&self) -> goff {
        self.quota.get()
    }

    pub(crate) fn have_quota(&self, size: goff) -> bool {
        self.quota.get() > size
    }

    pub(crate) fn alloc_mem(&self, size: goff) {
        assert!(self.have_quota(size));
        self.quota.replace(self.quota.get() - size);
    }

    pub(crate) fn free_mem(&self, size: goff) {
        self.quota.replace(self.quota.get() + size);
    }
}

impl fmt::Debug for ChildMem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "ChildMem[quota={}]", self.quota.get(),)
    }
}

#[derive(Default)]
pub struct Resources {
    childs: Vec<(Id, Selector)>,
    services: Vec<(Id, Selector)>,
    sessions: Vec<(usize, Session)>,
    mem: Vec<(Option<Selector>, Allocation)>,
    tiles: Vec<(tiles::TileUsage, usize, Selector)>,
    sgates: Vec<SendGate>,
}

pub trait Child {
    fn id(&self) -> Id;
    fn layer(&self) -> u32;
    fn name(&self) -> &String;
    fn daemon(&self) -> bool;
    fn foreign(&self) -> bool;

    fn our_tile(&self) -> Rc<tiles::TileUsage>;
    fn child_tile(&self) -> Option<Rc<tiles::TileUsage>>;
    fn activity_sel(&self) -> Selector;
    fn activity_id(&self) -> tcu::ActId;
    fn resmng_sgate_sel(&self) -> Selector;

    fn subsys(&mut self) -> Option<&mut SubsystemBuilder>;
    fn mem(&self) -> &Rc<ChildMem>;
    fn cfg(&self) -> Rc<AppConfig>;
    fn res(&self) -> &Resources;
    fn res_mut(&mut self) -> &mut Resources;
    fn kmem(&self) -> Option<Rc<KMem>>;

    fn delegate(&self, src: Selector, dst: Selector) -> Result<(), Error> {
        let crd = CapRngDesc::new(CapType::OBJECT, src, 1);
        syscalls::exchange(self.activity_sel(), crd, dst, false)
    }
    fn obtain(&self, src: Selector) -> Result<Selector, Error> {
        let dst = Activity::own().alloc_sels(1);
        let own = CapRngDesc::new(CapType::OBJECT, dst, 1);
        syscalls::exchange(self.activity_sel(), own, src, true)?;
        Ok(dst)
    }

    fn has_service(&self, sel: Selector) -> bool {
        self.res().services.iter().any(|t| t.1 == sel)
    }

    fn reg_service(
        &mut self,
        srv_sel: Selector,
        sgate_sel: Selector,
        name: String,
        sessions: u32,
    ) -> Result<(), Error> {
        log!(
            crate::LOG_SERV,
            "{}: reg_serv(srv_sel={}, sgate_sel={}, name={}, sessions={})",
            self.name(),
            srv_sel,
            sgate_sel,
            name,
            sessions,
        );

        let cfg = self.cfg();
        let sdesc = cfg
            .get_service(&name)
            .ok_or_else(|| Error::new(Code::InvArgs))?;
        if sdesc.is_used() {
            return Err(Error::new(Code::Exists));
        }

        let our_srv = self.obtain(srv_sel)?;
        let our_sgate = self.obtain(sgate_sel)?;
        let id = services::add_service(
            self.id(),
            our_srv,
            our_sgate,
            sdesc.name().global().to_string(),
            sessions,
            true,
        )?;

        sdesc.mark_used();
        self.res_mut().services.push((id, srv_sel));

        Ok(())
    }

    fn unreg_service(&mut self, sel: Selector) -> Result<(), Error> {
        log!(crate::LOG_SERV, "{}: unreg_serv(sel={})", self.name(), sel);

        let services = &mut self.res_mut().services;
        let sid = services
            .iter()
            .position(|t| t.1 == sel)
            .ok_or_else(|| Error::new(Code::InvArgs))
            .map(|idx| services.remove(idx).0)?;
        let serv = services::remove_service(sid);

        self.cfg().unreg_service(serv.name());
        Ok(())
    }

    fn alloc_local(&mut self, size: goff, perm: Perm) -> Result<MemGate, Error> {
        log!(
            crate::LOG_MEM,
            "{}: allocate_local(size={:#x}, perm={:?})",
            self.name(),
            size,
            perm
        );

        if !self.mem().have_quota(size) {
            return Err(Error::new(Code::NoSpace));
        }

        let alloc = self.mem().pool.borrow_mut().allocate(size)?;
        let mem_sel = self.mem().pool.borrow().mem_cap(alloc.slice_id());
        let mgate = MemGate::new_bind(mem_sel).derive(alloc.addr(), alloc.size() as usize, perm)?;
        // TODO this memory is currently only free'd on child exit
        self.add_mem(alloc, None);
        Ok(mgate)
    }

    fn alloc_mem(&mut self, dst_sel: Selector, size: goff, perm: Perm) -> Result<(), Error> {
        log!(
            crate::LOG_MEM,
            "{}: allocate(dst_sel={}, size={:#x}, perm={:?})",
            self.name(),
            dst_sel,
            size,
            perm
        );

        if !self.mem().have_quota(size) {
            return Err(Error::new(Code::NoSpace));
        }

        let alloc = self.mem().pool.borrow_mut().allocate(size)?;
        let mem_sel = self.mem().pool.borrow().mem_cap(alloc.slice_id());
        self.add_child_mem(alloc, mem_sel, dst_sel, perm)
    }
    fn alloc_mem_at(
        &mut self,
        dst_sel: Selector,
        offset: goff,
        size: goff,
        perm: Perm,
    ) -> Result<(), Error> {
        log!(
            crate::LOG_MEM,
            "{}: allocate_at(dst_sel={}, size={:#x}, offset={:#x}, perm={:?})",
            self.name(),
            dst_sel,
            size,
            offset,
            perm
        );

        let alloc = self
            .mem()
            .pool
            .borrow_mut()
            .allocate_at(offset, size, perm)?;
        let mem_sel = self.mem().pool.borrow().mem_cap(alloc.slice_id());
        self.add_child_mem(alloc, mem_sel, dst_sel, perm)
    }
    fn add_child_mem(
        &mut self,
        alloc: Allocation,
        mem_sel: Selector,
        dst_sel: Selector,
        perm: Perm,
    ) -> Result<(), Error> {
        syscalls::derive_mem(
            self.activity_sel(),
            dst_sel,
            mem_sel,
            alloc.addr(),
            alloc.size() as usize,
            perm,
        )
        .map_err(|e| {
            self.mem().pool.borrow_mut().free(alloc);
            e
        })?;

        self.add_mem(alloc, Some(dst_sel));
        Ok(())
    }
    fn add_mem(&mut self, alloc: Allocation, dst_sel: Option<Selector>) {
        self.res_mut().mem.push((dst_sel, alloc));
        if !self.mem().pool.borrow().slices()[alloc.slice_id()].in_reserved_mem() {
            self.mem().alloc_mem(alloc.size());
        }
        log!(
            crate::LOG_MEM,
            "{}: added {:?} (quota left: {})",
            self.name(),
            alloc,
            self.mem().quota.get(),
        );
    }

    fn free_mem(&mut self, sel: Selector) -> Result<(), Error> {
        let idx = self
            .res_mut()
            .mem
            .iter()
            .position(|(s, _)| match s {
                Some(s) => *s == sel,
                _ => false,
            })
            .ok_or_else(|| Error::new(Code::InvArgs))?;
        self.remove_mem_by_idx(idx);
        Ok(())
    }
    fn remove_mem_by_idx(&mut self, idx: usize) {
        let (sel, alloc) = self.res_mut().mem.remove(idx);
        if let Some(s) = sel {
            let crd = CapRngDesc::new(CapType::OBJECT, s, 1);
            // ignore failures here; maybe the activity is already gone
            syscalls::revoke(self.activity_sel(), crd, true).ok();
        }

        log!(
            crate::LOG_MEM,
            "{}: removed {:?} (quota left: {})",
            self.name(),
            alloc,
            self.mem().quota.get()
        );
        self.mem().pool.borrow_mut().free(alloc);
        if !self.mem().pool.borrow().slices()[alloc.slice_id()].in_reserved_mem() {
            self.mem().free_mem(alloc.size());
        }
    }

    fn use_rgate(&mut self, name: &str, sel: Selector) -> Result<(u32, u32), Error> {
        log!(
            crate::LOG_GATE,
            "{}: use_rgate(name={}, sel={})",
            self.name(),
            name,
            sel
        );

        let cfg = self.cfg();
        let rdesc = cfg
            .get_rgate(name)
            .ok_or_else(|| Error::new(Code::InvArgs))?;

        let gates = gates::get();
        let rgate = gates.get(rdesc.name().global()).unwrap();
        self.delegate(rgate.sel(), sel)?;
        Ok((
            math::next_log2(rgate.size()),
            math::next_log2(rgate.max_msg_size()),
        ))
    }
    fn use_sgate(&mut self, name: &str, sel: Selector) -> Result<(), Error> {
        log!(
            crate::LOG_GATE,
            "{}: use_sgate(name={}, sel={})",
            self.name(),
            name,
            sel
        );

        let cfg = self.cfg();
        let sdesc = cfg
            .get_sgate(name)
            .ok_or_else(|| Error::new(Code::InvArgs))?;
        if sdesc.is_used() {
            return Err(Error::new(Code::Exists));
        }

        let gates = gates::get();
        let rgate = gates.get(sdesc.name().global()).unwrap();

        let sgate = SendGate::new_with(
            SGateArgs::new(rgate)
                .credits(sdesc.credits())
                .label(sdesc.label()),
        )?;
        self.delegate(sgate.sel(), sel)?;

        sdesc.mark_used();
        self.res_mut().sgates.push(sgate);
        Ok(())
    }
    fn use_sem(&mut self, name: &str, sel: Selector) -> Result<(), Error> {
        log!(
            crate::LOG_SEM,
            "{}: use_sem(name={}, sel={})",
            self.name(),
            name,
            sel
        );

        let cfg = self.cfg();
        let sdesc = cfg.get_sem(name).ok_or_else(|| Error::new(Code::InvArgs))?;

        let sems = sems::get();
        let sem = sems
            .get(sdesc.name().global())
            .ok_or_else(|| Error::new(Code::NotFound))?;
        self.delegate(sem.sel(), sel)
    }

    fn get_serial(&mut self, sel: Selector) -> Result<(), Error> {
        log!(
            crate::LOG_SERIAL,
            "{}: get_serial(sel={})",
            self.name(),
            sel
        );

        let cfg = self.cfg();
        if cfg.alloc_serial() {
            self.delegate(subsys::SERIAL_RGATE_SEL, sel)
        }
        else {
            Err(Error::new(Code::InvArgs))
        }
    }

    fn alloc_tile(
        &mut self,
        sel: Selector,
        desc: kif::TileDesc,
    ) -> Result<(tcu::TileId, kif::TileDesc), Error> {
        log!(
            crate::LOG_TILES,
            "{}: alloc_tile(sel={}, desc={:?})",
            self.name(),
            sel,
            desc
        );

        let cfg = self.cfg();
        let idx = cfg.get_pe_idx(desc)?;
        let tile_usage = tiles::get().find_and_alloc(desc)?;

        // give this tile access to the same memory regions the child's tile has access to
        // TODO later we could allow childs to customize that
        tile_usage.inherit_mem_regions(&self.our_tile())?;

        self.delegate(tile_usage.tile_obj().sel(), sel)?;

        let tile_id = tile_usage.tile_id();
        let desc = tile_usage.tile_obj().desc();
        self.res_mut().tiles.push((tile_usage, idx, sel));
        cfg.alloc_tile(idx);

        Ok((tile_id, desc))
    }

    fn free_tile(&mut self, sel: Selector) -> Result<(), Error> {
        log!(crate::LOG_TILES, "{}: free_tile(sel={})", self.name(), sel);

        let idx = self
            .res_mut()
            .tiles
            .iter()
            .position(|(_, _, psel)| *psel == sel)
            .ok_or_else(|| Error::new(Code::InvArgs))?;
        self.remove_pe_by_idx(idx)?;

        Ok(())
    }

    fn remove_pe_by_idx(&mut self, idx: usize) -> Result<(), Error> {
        let (tile_usage, idx, ep_sel) = self.res_mut().tiles.remove(idx);
        log!(
            crate::LOG_TILES,
            "{}: removed tile (id={}, sel={})",
            self.name(),
            tile_usage.tile_id(),
            ep_sel
        );

        let cfg = self.cfg();
        let crd = CapRngDesc::new(CapType::OBJECT, ep_sel, 1);
        // TODO if that fails, we need to kill this child because otherwise we don't get the tile back
        syscalls::revoke(self.activity_sel(), crd, true).ok();
        cfg.free_tile(idx);

        Ok(())
    }

    fn remove_resources_async(&mut self) {
        while !self.res().sessions.is_empty() {
            let (idx, sess) = self.res_mut().sessions.remove(0);
            self.cfg().close_session(idx);
            sess.close_async(self.id()).ok();
        }

        while !self.res().services.is_empty() {
            let (id, _) = self.res_mut().services.remove(0);
            let serv = services::remove_service(id);
            self.cfg().unreg_service(serv.name());
        }

        while !self.res().mem.is_empty() {
            self.remove_mem_by_idx(0);
        }

        while !self.res().tiles.is_empty() {
            self.remove_pe_by_idx(0).ok();
        }
    }
}

pub fn add_child(
    id: Id,
    act_id: tcu::ActId,
    act_sel: Selector,
    rgate: &RecvGate,
    sgate_sel: Selector,
    name: String,
) -> Result<(), Error> {
    let mut childs = borrow_mut();
    let nid = childs.next_id();
    let child = childs.child_by_id_mut(id).unwrap();
    let our_sel = child.obtain(act_sel)?;
    let child_name = format!("{}.{}", child.name(), name);

    log!(
        crate::LOG_CHILD,
        "{}: add_child(act={}, name={}, sgate_sel={}) -> child(id={}, name={})",
        child.name(),
        act_sel,
        name,
        sgate_sel,
        nid,
        child_name
    );

    if child.res().childs.iter().any(|c| c.1 == act_sel) {
        return Err(Error::new(Code::Exists));
    }

    #[allow(clippy::useless_conversion)]
    let sgate = SendGate::new_with(
        SGateArgs::new(rgate)
            .credits(1)
            .label(tcu::Label::from(nid)),
    )?;
    let our_sg_sel = sgate.sel();
    let nchild = Box::new(ForeignChild::new(
        nid,
        child.layer() + 1,
        child_name,
        // actually, we don't know the tile it's running on. But the TileUsage is only used to set
        // the PMP EPs and currently, no child can actually influence these. For that reason,
        // all childs get the same PMP EPs, so that we can also give the same PMP EPs to childs
        // of childs.
        child.our_tile(),
        act_id,
        our_sel,
        sgate,
        child.cfg(),
        child.mem().clone(),
    ));
    nchild.delegate(our_sg_sel, sgate_sel)?;

    child.res_mut().childs.push((nid, act_sel));
    childs.add(nchild);
    Ok(())
}

pub fn open_session_async(id: Id, dst_sel: Selector, name: &str) -> Result<(), Error> {
    let (sname, sarg) = {
        let mut childs = borrow_mut();
        let child = childs.child_by_id_mut(id).unwrap();
        log!(
            crate::LOG_SERV,
            "{}: open_sess(dst_sel={}, name={})",
            child.name(),
            dst_sel,
            name
        );

        let cfg = child.cfg();
        let (_idx, sdesc) = cfg
            .get_session(name)
            .ok_or_else(|| Error::new(Code::InvArgs))?;
        if sdesc.is_used() {
            return Err(Error::new(Code::Exists));
        }
        (sdesc.name().global().clone(), sdesc.arg().clone())
    };

    let serv = services::get_mut_by_name(&sname)?;
    let serv_sel = serv.sel();
    let sess = Session::new_async(id, dst_sel, serv, &sarg)?;

    // get child and session desc again
    let mut childs = borrow_mut();
    let child = childs.child_by_id_mut(id).unwrap();
    let cfg = child.cfg();
    let (idx, sdesc) = cfg
        .get_session(name)
        .ok_or_else(|| Error::new(Code::InvArgs))?;

    // check again if it's still unused, because of the async call above
    if sdesc.is_used() {
        return Err(Error::new(Code::Exists));
    }

    syscalls::get_sess(serv_sel, child.activity_sel(), dst_sel, sess.ident())?;

    sdesc.mark_used();
    child.res_mut().sessions.push((idx, sess));

    Ok(())
}

pub fn close_session_async(id: Id, sel: Selector) -> Result<(), Error> {
    let sess = {
        let mut childs = borrow_mut();
        let child = childs.child_by_id_mut(id).unwrap();

        log!(crate::LOG_SERV, "{}: close_sess(sel={})", child.name(), sel);

        let (cfg_idx, sess) = {
            let sessions = &mut child.res_mut().sessions;
            sessions
                .iter()
                .position(|(_, s)| s.sel() == sel)
                .ok_or_else(|| Error::new(Code::InvArgs))
                .map(|res_idx| sessions.remove(res_idx))
        }?;

        child.cfg().close_session(cfg_idx);
        sess
    };

    sess.close_async(id)
}

pub fn rem_child_async(id: Id, act_sel: Selector) -> Result<(), Error> {
    let cid = {
        let mut childs = borrow_mut();
        let child = childs.child_by_id_mut(id).unwrap();

        log!(
            crate::LOG_CHILD,
            "{}: rem_child(act={})",
            child.name(),
            act_sel
        );

        let idx = child
            .res()
            .childs
            .iter()
            .position(|c| c.1 == act_sel)
            .ok_or_else(|| Error::new(Code::InvArgs))?;
        let cid = child.res().childs[idx].0;
        child.res_mut().childs.remove(idx);
        cid
    };

    ChildManager::remove_rec_async(cid);
    Ok(())
}

pub fn get_info(id: Id, idx: Option<usize>) -> Result<ResMngActInfoResult, Error> {
    let layer = {
        let mut childs = borrow_mut();
        let child = childs.child_by_id_mut(id).unwrap();
        if !child.cfg().can_get_info() {
            return Err(Error::new(Code::NoPerm));
        }
        child.layer()
    };

    let (parent_num, parent_layer) = if let Some(presmng) = Activity::own().resmng() {
        match presmng.get_activity_count() {
            Err(e) if e.code() == Code::NoPerm => (0, 0),
            Err(e) => return Err(e),
            Ok(res) => res,
        }
    }
    else {
        (0, 0)
    };

    let own_num = {
        let mut childs = borrow_mut();
        let mut own_num = childs.ids.len() + 1;
        for id in childs.ids.clone() {
            if childs.child_by_id_mut(id).unwrap().subsys().is_some() {
                own_num -= 1;
            }
        }
        own_num
    };

    if let Some(mut idx) = idx {
        if idx < parent_num {
            Ok(ResMngActInfoResult::Info(
                Activity::own().resmng().unwrap().get_activity_info(idx)?,
            ))
        }
        else if idx - parent_num >= own_num {
            Err(Error::new(Code::NotFound))
        }
        else {
            idx -= parent_num;

            // the first is always us
            if idx == 0 {
                let kmem_quota = Activity::own().kmem().quota()?;
                let tile_quota = Activity::own().tile().quota()?;
                let mem = memory::container();
                return Ok(ResMngActInfoResult::Info(ResMngActInfo {
                    id: Activity::own().id(),
                    layer: parent_layer + 0,
                    name: env::args().next().unwrap().to_string(),
                    daemon: true,
                    umem: Quota::new(
                        parent_num as QuotaId,
                        mem.capacity() as usize,
                        mem.available() as usize,
                    ),
                    kmem: kmem_quota,
                    eps: *tile_quota.endpoints(),
                    time: *tile_quota.time(),
                    pts: *tile_quota.page_tables(),
                    tile: Activity::own().tile_id(),
                }));
            }
            idx -= 1;

            // find the next non-subsystem child
            let mut childs = borrow_mut();
            let act = loop {
                let cid = childs.ids[idx];
                let act = childs.child_by_id_mut(cid).unwrap();
                if act.subsys().is_none() {
                    break act;
                }
                idx += 1;
            };

            let kmem_quota = act
                .kmem()
                .map(|km| km.quota())
                .unwrap_or_else(|| Ok(Quota::default()))?;
            let tile_quota = act
                .child_tile()
                .map(|tile| tile.tile_obj().quota())
                .unwrap_or_else(|| Ok(TileQuota::default()))?;
            Ok(ResMngActInfoResult::Info(ResMngActInfo {
                id: act.activity_id(),
                layer: parent_layer + act.layer(),
                name: act.name().to_string(),
                daemon: act.daemon(),
                umem: Quota::new(
                    parent_num as QuotaId + act.mem().id as QuotaId,
                    act.mem().total as usize,
                    act.mem().quota.get() as usize,
                ),
                kmem: kmem_quota,
                eps: *tile_quota.endpoints(),
                time: *tile_quota.time(),
                pts: *tile_quota.page_tables(),
                tile: act.our_tile().tile_id(),
            }))
        }
    }
    else {
        let total = own_num + parent_num;
        Ok(ResMngActInfoResult::Count((total, layer)))
    }
}

pub struct OwnChild {
    id: Id,
    // the activity has to be dropped before we drop the tile
    activity: Option<RunningProgramActivity>,
    our_tile: Rc<tiles::TileUsage>,
    child_tile: Rc<tiles::TileUsage>,
    name: String,
    args: Vec<String>,
    cfg: Rc<AppConfig>,
    mem: Rc<ChildMem>,
    res: Resources,
    sub: Option<SubsystemBuilder>,
    daemon: bool,
    kmem: Rc<KMem>,
}

impl OwnChild {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Id,
        our_tile: Rc<tiles::TileUsage>,
        child_tile: Rc<tiles::TileUsage>,
        args: Vec<String>,
        daemon: bool,
        kmem: Rc<KMem>,
        mem: Rc<ChildMem>,
        cfg: Rc<AppConfig>,
        sub: Option<SubsystemBuilder>,
    ) -> Self {
        OwnChild {
            id,
            our_tile,
            child_tile,
            name: cfg.name().to_string(),
            args,
            cfg,
            mem,
            res: Resources::default(),
            sub,
            daemon,
            activity: None,
            kmem,
        }
    }

    pub fn start(
        &mut self,
        act: ChildActivity,
        program: Option<(&mut dyn Mapper, FileRef<dyn File>)>,
    ) -> Result<(), Error> {
        log!(
            crate::LOG_DEF,
            "Starting boot module '{}' on tile{} with arguments {:?}",
            self.name(),
            self.child_tile().unwrap().tile_id(),
            &self.args[1..]
        );

        self.activity = Some(act.exec_file(program, &self.args)?);

        Ok(())
    }

    pub fn has_unmet_reqs(&self) -> bool {
        for sess in self.cfg().sessions() {
            if sess.is_dep() && services::get_mut_by_name(sess.name().global()).is_err() {
                return true;
            }
        }
        for scrt in self.cfg().sess_creators() {
            if services::get_mut_by_name(scrt.serv_name()).is_err() {
                return true;
            }
        }
        false
    }
}

impl Child for OwnChild {
    fn id(&self) -> Id {
        self.id
    }

    fn layer(&self) -> u32 {
        1
    }

    fn name(&self) -> &String {
        &self.name
    }

    fn daemon(&self) -> bool {
        self.daemon
    }

    fn foreign(&self) -> bool {
        false
    }

    fn our_tile(&self) -> Rc<tiles::TileUsage> {
        self.our_tile.clone()
    }

    fn child_tile(&self) -> Option<Rc<tiles::TileUsage>> {
        Some(self.child_tile.clone())
    }

    fn activity_id(&self) -> tcu::ActId {
        self.activity.as_ref().unwrap().activity().id()
    }

    fn activity_sel(&self) -> Selector {
        self.activity.as_ref().unwrap().activity().sel()
    }

    fn subsys(&mut self) -> Option<&mut SubsystemBuilder> {
        self.sub.as_mut()
    }

    fn resmng_sgate_sel(&self) -> Selector {
        self.activity
            .as_ref()
            .unwrap()
            .activity()
            .resmng_sel()
            .unwrap()
    }

    fn mem(&self) -> &Rc<ChildMem> {
        &self.mem
    }

    fn cfg(&self) -> Rc<AppConfig> {
        self.cfg.clone()
    }

    fn res(&self) -> &Resources {
        &self.res
    }

    fn res_mut(&mut self) -> &mut Resources {
        &mut self.res
    }

    fn kmem(&self) -> Option<Rc<KMem>> {
        Some(self.kmem.clone())
    }
}

impl fmt::Debug for OwnChild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "OwnChild[id={}, tile={}, args={:?}, kmem=KMem[sel={}, quota={}], mem={:?}]",
            self.id,
            self.child_tile.tile_id(),
            self.args,
            self.kmem.sel(),
            self.kmem.quota().unwrap().total(),
            self.mem,
        )
    }
}

pub struct ForeignChild {
    id: Id,
    act_id: tcu::ActId,
    layer: u32,
    name: String,
    parent_tile: Rc<tiles::TileUsage>,
    cfg: Rc<AppConfig>,
    mem: Rc<ChildMem>,
    res: Resources,
    act_sel: Selector,
    _sgate: SendGate,
}

impl ForeignChild {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Id,
        layer: u32,
        name: String,
        parent_tile: Rc<tiles::TileUsage>,
        act_id: tcu::ActId,
        act_sel: Selector,
        sgate: SendGate,
        cfg: Rc<AppConfig>,
        mem: Rc<ChildMem>,
    ) -> Self {
        ForeignChild {
            id,
            layer,
            name,
            parent_tile,
            cfg,
            mem,
            res: Resources::default(),
            act_id,
            act_sel,
            _sgate: sgate,
        }
    }
}

impl Child for ForeignChild {
    fn id(&self) -> Id {
        self.id
    }

    fn layer(&self) -> u32 {
        self.layer
    }

    fn name(&self) -> &String {
        &self.name
    }

    fn daemon(&self) -> bool {
        false
    }

    fn foreign(&self) -> bool {
        true
    }

    fn our_tile(&self) -> Rc<tiles::TileUsage> {
        self.parent_tile.clone()
    }

    fn child_tile(&self) -> Option<Rc<tiles::TileUsage>> {
        None
    }

    fn activity_id(&self) -> tcu::ActId {
        self.act_id
    }

    fn activity_sel(&self) -> Selector {
        self.act_sel
    }

    fn subsys(&mut self) -> Option<&mut SubsystemBuilder> {
        None
    }

    fn resmng_sgate_sel(&self) -> Selector {
        self._sgate.sel()
    }

    fn mem(&self) -> &Rc<ChildMem> {
        &self.mem
    }

    fn cfg(&self) -> Rc<AppConfig> {
        self.cfg.clone()
    }

    fn res(&self) -> &Resources {
        &self.res
    }

    fn res_mut(&mut self) -> &mut Resources {
        &mut self.res
    }

    fn kmem(&self) -> Option<Rc<KMem>> {
        None
    }
}

impl fmt::Debug for ForeignChild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "ForeignChild[id={}, mem={:?}]", self.id, self.mem)
    }
}

bitflags! {
    struct Flags : u64 {
        const STARTING = 1;
        const SHUTDOWN = 2;
    }
}

pub struct ChildManager {
    flags: Flags,
    childs: Treap<Id, Box<dyn Child>>,
    ids: Vec<Id>,
    next_id: Id,
    daemons: usize,
    foreigns: usize,
}

static MNG: StaticRefCell<ChildManager> = StaticRefCell::new(ChildManager::new());

pub fn borrow_mut() -> RefMut<'static, ChildManager> {
    // let mut bt = [0usize; 16];
    // let count = backtrace::collect(bt.as_mut());
    // println!("Backtrace:");
    // for i in 0..count {
    //     println!("  {:#x}", bt[i]);
    // }

    MNG.borrow_mut()
}

impl ChildManager {
    pub const fn new() -> Self {
        ChildManager {
            flags: Flags::STARTING,
            childs: Treap::new(),
            ids: Vec::new(),
            next_id: 0,
            daemons: 0,
            foreigns: 0,
        }
    }

    pub fn should_stop(&self) -> bool {
        // don't stop if we didn't have a child yet. this is necessary, because we use derive_srv
        // asynchronously and thus switch to a different thread while starting a subsystem. thus, if
        // the subsystem is the first child, we would stop without waiting without this workaround.
        !self.flags.contains(Flags::STARTING) && self.children() == 0
    }

    pub fn children(&self) -> usize {
        self.ids.len()
    }

    pub fn daemons(&self) -> usize {
        self.daemons
    }

    pub fn foreigns(&self) -> usize {
        self.foreigns
    }

    pub fn next_id(&mut self) -> Id {
        self.next_id
    }

    pub fn alloc_id(&mut self) -> Id {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub fn add(&mut self, child: Box<dyn Child>) {
        if child.daemon() {
            self.daemons += 1;
        }
        if child.foreign() {
            self.foreigns += 1;
            self.next_id += 1;
        }
        self.ids.push(child.id());
        self.childs.insert(child.id(), child);
        // now that we have a child, we want to stop as soon as we've no childs anymore
        self.flags.remove(Flags::STARTING);
    }

    pub fn child_by_id(&self, id: Id) -> Option<&dyn Child> {
        self.childs.get(&id).map(|c| c.as_ref())
    }

    pub fn child_by_id_mut(&mut self, id: Id) -> Option<&mut (dyn Child + 'static)> {
        self.childs.get_mut(&id).map(|c| c.as_mut())
    }

    pub fn start_waiting(&mut self, event: u64) {
        let mut sels = Vec::new();
        for id in &self.ids {
            let child = self.child_by_id(*id).unwrap();
            // don't wait for foreign childs, because that's the responsibility of its parent
            if !child.foreign() {
                sels.push(child.activity_sel());
            }
        }

        syscalls::activity_wait(&sels, event).unwrap();
    }

    pub fn handle_upcall_async(msg: &'static tcu::Message) {
        let upcall = msg.get_data::<kif::upcalls::DefaultUpcall>();

        match kif::upcalls::Operation::from(upcall.opcode) {
            kif::upcalls::Operation::ACT_WAIT => Self::upcall_wait_act_async(msg),
            kif::upcalls::Operation::DERIVE_SRV => Self::upcall_derive_srv(msg),
            _ => panic!("Unexpected upcall {}", upcall.opcode),
        }

        let mut reply_buf = MsgBuf::borrow_def();
        reply_buf.set(kif::DefaultReply { error: 0 });
        RecvGate::upcall()
            .reply(&reply_buf, msg)
            .expect("Upcall reply failed");
    }

    fn upcall_wait_act_async(msg: &'static tcu::Message) {
        let upcall = msg.get_data::<kif::upcalls::ActivityWait>();

        Self::kill_child_async(upcall.act_sel as Selector, upcall.exitcode as i32);

        // wait for the next
        {
            let mut childs = borrow_mut();
            let no_wait_childs = childs.daemons() + childs.foreigns();
            if !childs.flags.contains(Flags::SHUTDOWN) && childs.children() == no_wait_childs {
                childs.flags.set(Flags::SHUTDOWN, true);
                drop(childs);
                Self::kill_daemons_async();
                services::shutdown_async();
            }
        }

        let mut childs = borrow_mut();
        if !childs.should_stop() {
            childs.start_waiting(1);
        }
    }

    fn upcall_derive_srv(msg: &'static tcu::Message) {
        let upcall = msg.get_data::<kif::upcalls::DeriveSrv>();

        thread::notify(upcall.def.event, Some(msg));
    }

    pub fn kill_child_async(sel: Selector, exitcode: i32) {
        let maybe_id = {
            let childs = borrow_mut();
            childs.sel_to_id(sel)
        };

        if let Some(id) = maybe_id {
            let child = Self::remove_rec_async(id).unwrap();

            if exitcode != 0 {
                println!("Child '{}' exited with exitcode {}", child.name(), exitcode);
            }
        }
    }

    fn kill_daemons_async() {
        let ids = borrow_mut().ids.clone();
        for id in ids {
            // kill all daemons that didn't register a service
            let can_kill = {
                let childs = borrow_mut();
                let child = childs.child_by_id(id).unwrap();
                if child.daemon() && child.res().services.is_empty() {
                    log!(crate::LOG_CHILD, "Killing child '{}'", child.name());
                    true
                }
                else {
                    false
                }
            };

            if can_kill {
                Self::remove_rec_async(id).unwrap();
            }
        }
    }

    fn remove_rec_async(id: Id) -> Option<Box<dyn Child>> {
        let maybe_child = {
            let mut childs = borrow_mut();
            childs.childs.remove(&id)
        };

        if let Some(mut child) = maybe_child {
            log!(crate::LOG_CHILD, "Removing child '{}'", child.name());

            // let a potential ongoing async. operation fail
            events::remove_child(id);

            // first, revoke the child's SendGate
            syscalls::revoke(
                Activity::own().sel(),
                CapRngDesc::new(CapType::OBJECT, child.resmng_sgate_sel(), 1),
                true,
            )
            .ok();
            // now remove all potentially pending messages from the child
            #[allow(clippy::useless_conversion)]
            crate::requests::rgate().drop_msgs_with(child.id().into());

            for csel in &child.res().childs {
                Self::remove_rec_async(csel.0);
            }
            child.remove_resources_async();

            let mut childs = borrow_mut();
            childs.ids.retain(|&i| i != id);
            if child.daemon() {
                childs.daemons -= 1;
            }
            if child.foreign() {
                childs.foreigns -= 1;
            }

            log!(crate::LOG_CHILD, "Removed child '{}'", child.name());

            Some(child)
        }
        else {
            None
        }
    }

    fn sel_to_id(&self, sel: Selector) -> Option<Id> {
        self.ids
            .iter()
            .find(|&&id| {
                let child = self.child_by_id(id).unwrap();
                child.activity_sel() == sel
            })
            .copied()
    }
}
