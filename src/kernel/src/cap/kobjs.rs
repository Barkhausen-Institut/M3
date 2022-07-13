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

use base::cell::{Cell, Ref, RefCell, RefMut, StaticCell};
use base::col::ToString;
use base::errors::{Code, Error, VerboseError};
use base::format;
use base::goff;
use base::kif::{self, tilemux::QuotaId};
use base::mem::{size_of, GlobAddr};
use base::rc::{Rc, SRc, Weak};
use base::tcu::{self, EpId, Label, TileId};

use core::fmt;
use core::ptr;

use crate::com::Service;
use crate::mem;
use crate::tiles::{tilemng, Activity, State, TileMux};

#[derive(Clone)]
pub enum KObject {
    RGate(SRc<RGateObject>),
    SGate(SRc<SGateObject>),
    MGate(SRc<MGateObject>),
    Map(SRc<MapObject>),
    Serv(SRc<ServObject>),
    Sess(SRc<SessObject>),
    Sem(SRc<SemObject>),
    // Only ActManager owns a activity (Rc<Activity>). Break cycle here by using Weak
    Activity(Weak<Activity>),
    KMem(SRc<KMemObject>),
    Tile(SRc<TileObject>),
    EP(Rc<EPObject>),
}

const fn kobj_size<T>() -> usize {
    let size = size_of::<T>();
    if size <= 64 {
        64 + crate::slab::HEADER_SIZE
    }
    else if size <= 128 {
        128 + crate::slab::HEADER_SIZE
    }
    else {
        // since we are using musl's heap, it's hard to say what the overhead per allocation is.
        // that depends on whether we needed a new "group" or not, for example. as an estimate use
        // 64 bytes.
        size + 64
    }
}

static KOBJ_SIZES: [usize; 11] = [
    kobj_size::<SGateObject>(),
    kobj_size::<RGateObject>(),
    kobj_size::<MGateObject>(),
    kobj_size::<MapObject>(),
    kobj_size::<ServObject>(),
    kobj_size::<SessObject>(),
    kobj_size::<Activity>(),
    kobj_size::<SemObject>(),
    kobj_size::<KMemObject>(),
    // assume pessimistically that each TileObject has its own EPQuota
    kobj_size::<TileObject>() + kobj_size::<EPQuota>(),
    kobj_size::<EPObject>(),
];

impl KObject {
    pub fn size(&self) -> usize {
        // get the index in the enum
        let idx: usize = unsafe { *(self as *const _ as *const usize) };
        KOBJ_SIZES[idx]
    }
}

impl fmt::Debug for KObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KObject::SGate(s) => write!(f, "{:?}", s),
            KObject::RGate(r) => write!(f, "{:?}", r),
            KObject::MGate(m) => write!(f, "{:?}", m),
            KObject::Map(m) => write!(f, "{:?}", m),
            KObject::Serv(s) => write!(f, "{:?}", s),
            KObject::Sess(s) => write!(f, "{:?}", s),
            KObject::Activity(v) => write!(f, "{:?}", v),
            KObject::Sem(s) => write!(f, "{:?}", s),
            KObject::KMem(k) => write!(f, "{:?}", k),
            KObject::Tile(p) => write!(f, "{:?}", p),
            KObject::EP(e) => write!(f, "{:?}", e),
        }
    }
}

pub struct GateEP {
    ep: Weak<EPObject>,
}

impl GateEP {
    fn new() -> Self {
        Self { ep: Weak::new() }
    }

    pub fn get_ep(&self) -> Option<Rc<EPObject>> {
        self.ep.upgrade()
    }

    pub fn set_ep(&mut self, o: &Rc<EPObject>) {
        self.ep = Rc::downgrade(o);
    }

    pub fn remove_ep(&mut self) {
        self.ep = Weak::new()
    }
}

pub enum GateObject {
    Recv(SRc<RGateObject>),
    Send(SRc<SGateObject>),
    Mem(SRc<MGateObject>),
}

impl GateObject {
    pub fn set_ep(&self, ep: &Rc<EPObject>) {
        match self {
            Self::Recv(g) => g.gep.borrow_mut().set_ep(ep),
            Self::Send(g) => g.gep.borrow_mut().set_ep(ep),
            Self::Mem(g) => g.gep.borrow_mut().set_ep(ep),
        }
    }

    pub fn remove_ep(&self) {
        match self {
            Self::Recv(g) => g.gep.borrow_mut().remove_ep(),
            Self::Send(g) => g.gep.borrow_mut().remove_ep(),
            Self::Mem(g) => g.gep.borrow_mut().remove_ep(),
        }
    }
}

pub struct RGateObject {
    gep: RefCell<GateEP>,
    loc: Cell<Option<(TileId, EpId)>>,
    addr: Cell<goff>,
    order: u32,
    msg_order: u32,
    serial: bool,
}

impl RGateObject {
    pub fn new(order: u32, msg_order: u32, serial: bool) -> SRc<Self> {
        SRc::new(Self {
            gep: RefCell::from(GateEP::new()),
            loc: Cell::from(None),
            addr: Cell::from(0),
            order,
            msg_order,
            serial,
        })
    }

    pub fn gate_ep_mut(&self) -> RefMut<'_, GateEP> {
        self.gep.borrow_mut()
    }

    pub fn location(&self) -> Option<(TileId, EpId)> {
        self.loc.get()
    }

    pub fn addr(&self) -> goff {
        self.addr.get()
    }

    pub fn order(&self) -> u32 {
        self.order
    }

    pub fn size(&self) -> usize {
        1 << self.order
    }

    pub fn msg_order(&self) -> u32 {
        self.msg_order
    }

    pub fn msg_size(&self) -> usize {
        1 << self.msg_order
    }

    pub fn activated(&self) -> bool {
        self.addr.get() != 0
    }

    pub fn activate(&self, tile: TileId, ep: EpId, addr: goff) {
        self.loc.replace(Some((tile, ep)));
        self.addr.replace(addr);
        if self.serial {
            crate::platform::init_serial(Some((tile, ep)));
        }
    }

    pub fn deactivate(&self) {
        self.addr.set(0);
        self.loc.set(None);
        if self.serial {
            crate::platform::init_serial(None);
        }
    }

    pub fn get_event(&self) -> thread::Event {
        self as *const Self as thread::Event
    }

    pub fn print_loc(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.loc.get() {
            Some((tile, ep)) => write!(f, "Tile{}:EP{}", tile, ep),
            None => write!(f, "?"),
        }
    }
}

impl fmt::Debug for RGateObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RGate[loc=")?;
        self.print_loc(f)?;
        write!(
            f,
            ", addr={:#x}, sz={:#x}, msz={:#x}]",
            self.addr.get(),
            self.size(),
            self.msg_size()
        )
    }
}

pub struct SGateObject {
    gep: RefCell<GateEP>,
    rgate: SRc<RGateObject>,
    label: Label,
    credits: u32,
}

impl SGateObject {
    pub fn new(rgate: &SRc<RGateObject>, label: Label, credits: u32) -> SRc<Self> {
        SRc::new(Self {
            gep: RefCell::from(GateEP::new()),
            rgate: rgate.clone(),
            label,
            credits,
        })
    }

    pub fn gate_ep(&self) -> Ref<'_, GateEP> {
        self.gep.borrow()
    }

    pub fn gate_ep_mut(&self) -> RefMut<'_, GateEP> {
        self.gep.borrow_mut()
    }

    pub fn rgate(&self) -> &SRc<RGateObject> {
        &self.rgate
    }

    pub fn label(&self) -> Label {
        self.label
    }

    pub fn credits(&self) -> u32 {
        self.credits
    }

    pub fn invalidate_reply_eps(&self) {
        // is the send gate activated?
        if let Some(sep) = self.gate_ep().get_ep() {
            // is the associated receive gate activated?
            if let Some((recv_tile, recv_ep)) = self.rgate().location() {
                let tilemux = tilemng::tilemux(sep.tile_id());
                tilemux
                    .invalidate_reply_eps(recv_tile, recv_ep, sep.ep())
                    .unwrap();
            }
        }
    }
}

impl fmt::Debug for SGateObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SGate[rgate=")?;
        self.rgate.print_loc(f)?;
        write!(f, ", lbl={:#x}, crd={}]", self.label, self.credits)
    }
}

pub struct MGateObject {
    gep: RefCell<GateEP>,
    mem: mem::Allocation,
    perms: kif::Perm,
    derived: bool,
}

impl MGateObject {
    pub fn new(mem: mem::Allocation, perms: kif::Perm, derived: bool) -> SRc<Self> {
        SRc::new(Self {
            gep: RefCell::from(GateEP::new()),
            mem,
            perms,
            derived,
        })
    }

    pub fn gate_ep(&self) -> Ref<'_, GateEP> {
        self.gep.borrow()
    }

    pub fn gate_ep_mut(&self) -> RefMut<'_, GateEP> {
        self.gep.borrow_mut()
    }

    pub fn tile_id(&self) -> TileId {
        self.mem.global().tile()
    }

    pub fn offset(&self) -> goff {
        self.mem.global().offset()
    }

    pub fn addr(&self) -> GlobAddr {
        self.mem.global()
    }

    pub fn size(&self) -> goff {
        self.mem.size()
    }

    pub fn perms(&self) -> kif::Perm {
        self.perms
    }
}

impl Drop for MGateObject {
    fn drop(&mut self) {
        // if it's not derived, it's always memory from mem-tiles
        if !self.derived {
            mem::borrow_mut().free(&self.mem);
        }
    }
}

impl fmt::Debug for MGateObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MGate[tile={}, addr={:?}, size={:#x}, perm={:?}, der={}]",
            self.tile_id(),
            self.addr(),
            self.size(),
            self.perms,
            self.derived
        )
    }
}

pub struct ServObject {
    serv: SRc<Service>,
    owner: bool,
    creator: usize,
}

impl ServObject {
    pub fn new(serv: SRc<Service>, owner: bool, creator: usize) -> SRc<Self> {
        SRc::new(Self {
            serv,
            owner,
            creator,
        })
    }

    pub fn service(&self) -> &SRc<Service> {
        &self.serv
    }

    pub fn creator(&self) -> usize {
        self.creator
    }
}

impl fmt::Debug for ServObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Serv[srv={:?}, owner={}, creator={}]",
            self.serv, self.owner, self.creator
        )
    }
}

pub struct SessObject {
    srv: SRc<ServObject>,
    creator: usize,
    ident: u64,
}

impl SessObject {
    pub fn new(srv: &SRc<ServObject>, creator: usize, ident: u64) -> SRc<Self> {
        SRc::new(Self {
            srv: srv.clone(),
            creator,
            ident,
        })
    }

    pub fn service(&self) -> &SRc<ServObject> {
        &self.srv
    }

    pub fn creator(&self) -> usize {
        self.creator
    }

    pub fn ident(&self) -> u64 {
        self.ident
    }
}

impl fmt::Debug for SessObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Sess[service={}, ident={:#x}]",
            self.service().service().name(),
            self.ident
        )
    }
}

pub struct SemObject {
    counter: Cell<u32>,
    waiters: Cell<i32>,
}

impl SemObject {
    pub fn new(counter: u32) -> SRc<Self> {
        SRc::new(Self {
            counter: Cell::from(counter),
            waiters: Cell::from(0),
        })
    }

    pub fn down_async(sem: &SRc<Self>) -> Result<(), Error> {
        while unsafe { ptr::read_volatile(sem.counter.as_ptr()) } == 0 {
            sem.waiters.set(sem.waiters.get() + 1);
            let event = sem.get_event();
            thread::wait_for(event);
            if unsafe { ptr::read_volatile(sem.waiters.as_ptr()) } == -1 {
                return Err(Error::new(Code::RecvGone));
            }
            sem.waiters.set(sem.waiters.get() - 1);
        }
        sem.counter.set(sem.counter.get() - 1);
        Ok(())
    }

    pub fn up(&self) {
        if self.waiters.get() > 0 {
            thread::notify(self.get_event(), None);
        }
        self.counter.set(self.counter.get() + 1);
    }

    pub fn revoke(&self) {
        if self.waiters.get() > 0 {
            thread::notify(self.get_event(), None);
        }
        self.waiters.set(-1);
    }

    fn get_event(&self) -> thread::Event {
        self as *const Self as thread::Event
    }
}

impl fmt::Debug for SemObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Sem[counter={}, waiters={}]",
            self.counter.get(),
            self.waiters.get()
        )
    }
}

pub struct EPQuota {
    id: QuotaId,
    total: u32,
    left: Cell<u32>,
}

impl EPQuota {
    pub fn new(eps: u32) -> Rc<Self> {
        static NEXT_ID: StaticCell<QuotaId> = StaticCell::new(0);
        let id = NEXT_ID.get();
        NEXT_ID.set(id + 1);

        Rc::new(Self {
            id,
            total: eps,
            left: Cell::from(eps),
        })
    }

    pub fn id(&self) -> QuotaId {
        self.id
    }

    pub fn total(&self) -> u32 {
        self.total
    }

    pub fn left(&self) -> u32 {
        self.left.get()
    }
}

#[derive(Debug)]
pub struct BWQuota {
    id: QuotaId,
    next_id: Rc<RefCell<QuotaId>>,
    rate: Cell<u32>,
}

impl BWQuota {
    pub fn new(id: QuotaId, next_id: Rc<RefCell<QuotaId>>, rate: u32) -> Rc<Self> {
        Rc::new(Self {
            id,
            next_id,
            rate: Cell::from(rate),
        })
    }

    pub fn id(&self) -> QuotaId {
        self.id
    }

    pub fn rate(&self) -> u32 {
        self.rate.get()
    }

    pub fn set(&self, rate: u32) {
        self.rate.set(rate);
    }

    pub fn derive(&self, rate: u32) -> Result<Rc<Self>, VerboseError> {
        // enough bandwidth for the derive?
        if self.rate() != tcu::MEM_BW_UNLIMITED && self.rate() < rate {
            return Err(VerboseError::new(
                Code::NoSpace,
                format!(
                    "Insufficient memory bandwidth (have {}, need {})",
                    self.rate(),
                    rate
                ),
            ));
        }

        // are all bandwidth registers already in use?
        let next_id = *self.next_id.borrow();
        if next_id == tcu::MAX_BW_REGS as QuotaId {
            return Err(VerboseError::new(
                Code::NoSpace,
                "All memory-bandwidth quotas in use".to_string(),
            ));
        }

        *self.next_id.borrow_mut() = next_id + 1;
        // unlimited quotas are not reduced, but stay unlimited
        if self.rate() != tcu::MEM_BW_UNLIMITED {
            self.rate.set(self.rate.get() - rate);
        }
        Ok(Self::new(next_id, self.next_id.clone(), rate))
    }
}

pub struct TileObject {
    tile: TileId,
    cur_acts: Cell<u32>,
    ep_quota: Rc<EPQuota>,
    bw_quota: Rc<BWQuota>,
    time_quota: QuotaId,
    pt_quota: QuotaId,
    derived: bool,
}

impl TileObject {
    pub fn new(
        tile: TileId,
        ep_quota: Rc<EPQuota>,
        bw_quota: Rc<BWQuota>,
        time_quota: QuotaId,
        pt_quota: QuotaId,
        derived: bool,
    ) -> SRc<Self> {
        let res = SRc::new(Self {
            tile,
            cur_acts: Cell::from(0),
            ep_quota: ep_quota.clone(),
            bw_quota: bw_quota.clone(),
            time_quota,
            pt_quota,
            derived,
        });
        klog!(
            TILES,
            "Tile[{}, {:#x}]: {} new TileObject with EPs={}, bw={}, time={}, pts={}",
            tile,
            &*res as *const _ as usize,
            if derived { "derived" } else { "created" },
            ep_quota.total,
            bw_quota.rate(),
            time_quota,
            pt_quota,
        );
        res
    }

    pub fn tile(&self) -> TileId {
        self.tile
    }

    pub fn derived(&self) -> bool {
        self.derived
    }

    pub fn activities(&self) -> u32 {
        self.cur_acts.get()
    }

    pub fn ep_quota(&self) -> &Rc<EPQuota> {
        &self.ep_quota
    }

    pub fn bw_quota(&self) -> &Rc<BWQuota> {
        &self.bw_quota
    }

    pub fn time_quota_id(&self) -> QuotaId {
        self.time_quota
    }

    pub fn pt_quota_id(&self) -> QuotaId {
        self.pt_quota
    }

    pub fn has_quota(&self, eps: u32) -> bool {
        self.ep_quota.left() >= eps
    }

    pub fn add_activity(&self) {
        self.cur_acts.set(self.activities() + 1);
    }

    pub fn rem_activity(&self) {
        assert!(self.activities() > 0);
        self.cur_acts.set(self.activities() - 1);
    }

    pub fn alloc_eps(&self, eps: u32) {
        klog!(
            TILES,
            "Tile[{}, {:#x}]: allocating {} EPs ({} left)",
            self.tile,
            self as *const _ as usize,
            eps,
            self.ep_quota.left()
        );
        assert!(self.ep_quota.left() >= eps);
        self.ep_quota.left.set(self.ep_quota.left() - eps);
    }

    pub fn free_eps(&self, eps: u32) {
        assert!(self.ep_quota.left() + eps <= self.ep_quota.total);
        self.ep_quota.left.set(self.ep_quota.left() + eps);
        klog!(
            TILES,
            "Tile[{}, {:#x}]: freed {} EPs ({} left)",
            self.tile,
            self as *const _ as usize,
            eps,
            self.ep_quota.left()
        );
    }

    pub fn revoke_async(&self, parent: &TileObject) {
        // we free the EP quota if it's different from our parent's quota (only our own childs can
        // have the same EP quota, but they are already gone).
        if !Rc::ptr_eq(&self.ep_quota, &parent.ep_quota) {
            // grant the EPs back to our parent
            parent.free_eps(self.ep_quota.left());
            assert!(self.ep_quota.left() == self.ep_quota.total);
        }

        // same for time and pts: free the ones that are different
        let time = if self.time_quota != parent.time_quota {
            Some(self.time_quota)
        }
        else {
            None
        };
        let pts = if self.pt_quota != parent.pt_quota {
            Some(self.pt_quota)
        }
        else {
            None
        };
        if time.is_some() || pts.is_some() {
            TileMux::remove_quotas_async(tilemng::tilemux(self.tile), time, pts).ok();
        }
    }
}

impl fmt::Debug for TileObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Tile[id={}, eps={}, actitivies={}, derived={}]",
            self.tile,
            self.ep_quota.left(),
            self.activities(),
            self.derived,
        )
    }
}

pub struct EPObject {
    is_std: bool,
    gate: RefCell<Option<GateObject>>,
    act: Weak<Activity>,
    ep: EpId,
    replies: u32,
    tile: SRc<TileObject>,
}

impl EPObject {
    pub fn new(
        is_std: bool,
        act: Weak<Activity>,
        ep: EpId,
        replies: u32,
        tile: &SRc<TileObject>,
    ) -> Rc<Self> {
        let maybe_act = act.upgrade();
        let ep = Rc::new(Self {
            is_std,
            gate: RefCell::from(None),
            act,
            ep,
            replies,
            tile: tile.clone(),
        });
        if let Some(v) = maybe_act {
            v.add_ep(ep.clone());
        }
        ep
    }

    pub fn tile_id(&self) -> TileId {
        self.tile.tile()
    }

    pub fn activity(&self) -> Option<Rc<Activity>> {
        self.act.upgrade()
    }

    pub fn ep(&self) -> EpId {
        self.ep
    }

    pub fn replies(&self) -> u32 {
        self.replies
    }

    pub fn is_rgate(&self) -> bool {
        matches!(self.gate.borrow().as_ref(), Some(GateObject::Recv(_)))
    }

    pub fn set_gate(&self, g: GateObject) {
        self.gate.replace(Some(g));
    }

    pub fn revoke(ep: &Rc<Self>) {
        if let Some(v) = ep.act.upgrade() {
            v.rem_ep(ep);
        }
    }

    pub fn configure(ep: &Rc<Self>, gate: &KObject) {
        // create a gate object from the kobj
        let go = match gate {
            KObject::MGate(g) => GateObject::Mem(g.clone()),
            KObject::RGate(g) => GateObject::Recv(g.clone()),
            KObject::SGate(g) => GateObject::Send(g.clone()),
            _ => unreachable!(),
        };
        // we tell the gate object its gate object
        go.set_ep(ep);
        // we tell the endpoint its current gate object
        ep.set_gate(go);
    }

    pub fn deconfigure(&self, force: bool) -> Result<bool, Error> {
        let mut invalidated = false;
        if let Some(ref gate) = &*self.gate.borrow() {
            let tile_id = self.tile_id();

            // invalidate receive and send EPs
            match gate {
                GateObject::Recv(_) | GateObject::Send(_) => {
                    tilemng::tilemux(tile_id).invalidate_ep(
                        self.activity().unwrap().id(),
                        self.ep,
                        force,
                        true,
                    )?;
                    invalidated = true;
                },
                _ => {},
            }

            match gate {
                // invalidate reply EPs
                GateObject::Send(s) => s.invalidate_reply_eps(),
                // deactivate receive gate
                GateObject::Recv(r) => r.deactivate(),
                _ => {},
            }

            // we tell the gate that it's ep is no longer valid
            gate.remove_ep();
        }
        Ok(invalidated)
    }
}

impl Drop for EPObject {
    fn drop(&mut self) {
        if !self.is_std {
            tilemng::tilemux(self.tile.tile).free_eps(self.ep, 1 + self.replies);

            self.tile.free_eps(1 + self.replies);
        }
    }
}

impl fmt::Debug for EPObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EP[act={}, ep={}, replies={}, tile={:?}]",
            self.activity().unwrap().id(),
            self.ep,
            self.replies,
            self.tile
        )
    }
}

pub struct KMemObject {
    id: QuotaId,
    quota: usize,
    left: Cell<usize>,
}

impl KMemObject {
    pub fn new(quota: usize) -> SRc<Self> {
        static NEXT_ID: StaticCell<QuotaId> = StaticCell::new(0);
        let id = NEXT_ID.get();
        NEXT_ID.set(id + 1);

        let kmem = SRc::new(Self {
            id,
            quota,
            left: Cell::from(quota),
        });
        klog!(KMEM, "{:?} created", kmem);
        kmem
    }

    pub fn id(&self) -> QuotaId {
        self.id
    }

    pub fn quota(&self) -> usize {
        self.quota
    }

    pub fn left(&self) -> usize {
        self.left.get()
    }

    pub fn has_quota(&self, size: usize) -> bool {
        self.left.get() >= size
    }

    pub fn alloc(&self, act: &Activity, sel: kif::CapSel, size: usize) -> bool {
        klog!(
            KMEM,
            "{:?} Activity{}:{} allocates {}b (sel={})",
            self,
            act.id(),
            act.name(),
            size,
            sel,
        );

        if self.has_quota(size) {
            self.left.set(self.left() - size);
            true
        }
        else {
            false
        }
    }

    pub fn free(&self, act: &Activity, sel: kif::CapSel, size: usize) {
        assert!(self.left() + size <= self.quota);
        self.left.set(self.left() + size);

        klog!(
            KMEM,
            "{:?} Activity{}:{} freed {}b (sel={})",
            self,
            act.id(),
            act.name(),
            size,
            sel
        );
    }

    pub fn revoke(&self, act: &Activity, sel: kif::CapSel, parent: &KMemObject) {
        // grant the kernel memory back to our parent
        parent.free(act, sel, self.left());
        assert!(self.left() == self.quota);
    }
}

impl fmt::Debug for KMemObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KMem[id={}, quota={}, left={}]",
            self.id,
            self.quota,
            self.left()
        )
    }
}

impl Drop for KMemObject {
    fn drop(&mut self) {
        klog!(KMEM, "{:?} dropped", self);
        assert!(self.left() == self.quota);
    }
}

pub struct MapObject {
    glob: Cell<GlobAddr>,
    flags: Cell<kif::PageFlags>,
    mapped: Cell<bool>,
}

impl MapObject {
    pub fn new(glob: GlobAddr, flags: kif::PageFlags) -> SRc<Self> {
        SRc::new(Self {
            glob: Cell::from(glob),
            flags: Cell::from(flags),
            mapped: Cell::from(false),
        })
    }

    pub fn mapped(&self) -> bool {
        self.mapped.get()
    }

    pub fn global(&self) -> GlobAddr {
        self.glob.get()
    }

    pub fn flags(&self) -> kif::PageFlags {
        self.flags.get()
    }

    pub fn map_async(
        &self,
        act: &Activity,
        virt: goff,
        glob: GlobAddr,
        pages: usize,
        flags: kif::PageFlags,
    ) -> Result<(), Error> {
        TileMux::map_async(
            tilemng::tilemux(act.tile_id()),
            act.id(),
            virt,
            glob,
            pages,
            flags,
        )
        .map(|_| {
            self.glob.replace(glob);
            self.flags.replace(flags);
            self.mapped.set(true);
        })
    }

    pub fn unmap_async(&self, act: &Activity, virt: goff, pages: usize) {
        // TODO currently, it can happen that we've already stopped the activity, but still
        // accept/continue a syscall that inserts something into the activity's table.
        if act.state() != State::DEAD {
            TileMux::unmap_async(tilemng::tilemux(act.tile_id()), act.id(), virt, pages).ok();
        }
    }
}

impl fmt::Debug for MapObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Map[glob={:?}, flags={:#x}]",
            self.global(),
            self.flags()
        )
    }
}
