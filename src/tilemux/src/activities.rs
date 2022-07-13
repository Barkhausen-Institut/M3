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

use base::boxed::Box;
use base::cell::{LazyStaticUnsafeCell, StaticCell, StaticRefCell, StaticUnsafeCell};
use base::cfg;
use base::col::{BoxList, Vec};
use base::errors::{Code, Error};
use base::goff;
use base::impl_boxitem;
use base::kif;
use base::log;
use base::mem::{size_of, GlobAddr, MsgBuf};
use base::rc::Rc;
use base::tcu;
use base::time::{TimeDuration, TimeInstant};
use base::tmif;
use base::util::math;
use core::cmp;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use paging::{Allocator, Phys};

use crate::arch;
use crate::helper;
use crate::irqs;
use crate::pex_env;
use crate::quota::{self, PTQuota, Quota, TimeQuota};
use crate::sendqueue;
use crate::timer;
use crate::vma::PfState;

pub type Id = paging::ActId;

struct PTAllocator {
    act: Id,
    quota: Rc<PTQuota>,
}

impl Allocator for PTAllocator {
    fn allocate_pt(&mut self) -> Result<Phys, Error> {
        assert!(self.act != kif::tilemux::IDLE_ID);
        if self.quota.left() == 0 {
            return Err(Error::new(Code::NoSpace));
        }

        if let Some(pt) = PTS.borrow_mut().pop() {
            self.quota.set_left(self.quota.left() - 1);
            log!(
                crate::LOG_PTS,
                "Alloc PT {:#x} (quota[{}]: {}, total: {})",
                pt,
                self.quota.id(),
                self.quota.left(),
                PTS.borrow().len()
            );
            Ok(pt)
        }
        else {
            Err(Error::new(Code::NoSpace))
        }
    }

    fn translate_pt(&self, phys: Phys) -> usize {
        if BOOTSTRAP.get() {
            phys as usize
        }
        else {
            cfg::TILE_MEM_BASE + (phys as usize - cfg::MEM_OFFSET)
        }
    }

    fn free_pt(&mut self, phys: Phys) {
        log!(
            crate::LOG_PTS,
            "Free PT {:#x} (quota[{}]: {}, free: {})",
            phys,
            self.quota.id(),
            self.quota.left(),
            PTS.borrow().len()
        );
        PTS.borrow_mut().push(phys);
        self.quota.set_left(self.quota.left() + 1);
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum ActState {
    Running,
    Ready,
    Blocked,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ScheduleAction {
    Block,
    Yield,
    Preempt,
    Kill,
}

#[derive(PartialEq, Eq)]
pub enum ContResult {
    Waiting,
    Success,
    Failure,
}

#[derive(Debug)]
pub enum Event {
    Message(tcu::EpId),
    Interrupt(tmif::IRQId),
    EpInvalid,
    Timeout,
    Start,
}

pub struct Activity {
    state: ActState,
    prev: Option<NonNull<Activity>>,
    next: Option<NonNull<Activity>>,
    aspace: Option<paging::AddrSpace<PTAllocator>>,
    frames: Vec<Phys>,
    #[cfg(any(target_arch = "riscv64", target_arch = "x86_64"))]
    fpu_state: arch::FPUState,
    user_state: arch::State,
    user_state_addr: usize,
    scheduled: TimeInstant,
    time_quota: Rc<TimeQuota>,
    cpu_time: TimeDuration,
    ctxsws: u64,
    wait_timeout: bool,
    wait_irq: Option<tmif::IRQId>,
    wait_ep: Option<tcu::EpId>,
    irq_mask: u32,
    act_reg: tcu::Reg,
    eps_start: tcu::EpId,
    cmd: helper::TCUCmdState,
    pf_state: Option<PfState>,
    cont: Option<fn(&mut Activity) -> ContResult>,
    has_refs: bool,
}

/// A reference to an activity that ensures at runtime that there is always just one reference to
/// each activity at a time.
pub struct ActivityRef<'a> {
    act: &'a mut Activity,
}

impl<'m> ActivityRef<'m> {
    fn new(act: &'m mut Activity) -> Self {
        assert!(!act.has_refs);
        act.has_refs = true;
        Self { act }
    }
}

impl<'m> Drop for ActivityRef<'m> {
    fn drop(&mut self) {
        self.act.has_refs = false;
    }
}

impl<'m> Deref for ActivityRef<'m> {
    type Target = Activity;

    fn deref(&self) -> &Self::Target {
        self.act
    }
}

impl<'m> DerefMut for ActivityRef<'m> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.act
    }
}

impl_boxitem!(Activity);

// safety: we use the unsafe cell here, because it's not really possible to use a StaticRefCell or
// similar since we sometimes require access to two activities at a time. Therefore, we use an
// unsafe cell, but track the references per activity at runtime to ensure that there are never two
// mutable references to the same activity at the same time.
static ACTIVITIES: StaticUnsafeCell<[Option<NonNull<Activity>>; 64]> =
    StaticUnsafeCell::new([None; 64]);

static IDLE: LazyStaticUnsafeCell<Box<Activity>> = LazyStaticUnsafeCell::default();
static OUR: LazyStaticUnsafeCell<Box<Activity>> = LazyStaticUnsafeCell::default();
static CUR: StaticUnsafeCell<Option<Box<Activity>>> = StaticUnsafeCell::new(None);

static RDY: StaticRefCell<BoxList<Activity>> = StaticRefCell::new(BoxList::new());
static BLK: StaticRefCell<BoxList<Activity>> = StaticRefCell::new(BoxList::new());

static BOOTSTRAP: StaticCell<bool> = StaticCell::new(true);
static PTS: StaticRefCell<Vec<Phys>> = StaticRefCell::new(Vec::new());

pub fn init() {
    extern "C" {
        static _bss_end: usize;
    }

    let (frame, root_pt) = if pex_env().tile_desc.has_virtmem() {
        let (mem_tile, mem_base, mem_size, _) = tcu::TCU::unpack_mem_ep(0).unwrap();

        let base = GlobAddr::new_with(mem_tile, mem_base);

        // use the memory behind ourself for page tables
        let bss_end = unsafe { &_bss_end as *const _ as usize };
        let first_pt = bss_end / cfg::PAGE_SIZE;
        let first_pt = 1 + first_pt as Phys - (cfg::MEM_OFFSET / cfg::PAGE_SIZE) as Phys;
        // we don't need that many PTs here; 512 are enough for now
        let pt_count = cmp::min(first_pt + 512, (mem_size as usize / cfg::PAGE_SIZE) as Phys);
        {
            let mut pts = PTS.borrow_mut();
            pts.reserve((pt_count - first_pt) as usize);
            for i in first_pt..pt_count {
                pts.push(cfg::MEM_OFFSET as Phys + i * cfg::PAGE_SIZE as Phys);
            }
        }

        let mut allocator = PTAllocator {
            act: kif::tilemux::ACT_ID,
            quota: Quota::new(0, None, PTS.borrow().len()),
        };
        let frame = allocator.allocate_pt().unwrap();
        (frame, Some(base + (frame - cfg::MEM_OFFSET as Phys)))
    }
    else {
        (0, None)
    };

    quota::init(PTS.borrow().len());

    let idle_quota = quota::get_time(quota::IDLE_ID).unwrap();
    idle_quota.attach();
    let our_quota = quota::get_time(quota::IDLE_ID).unwrap();
    our_quota.attach();

    // safety: there are no other references to IDLE or OUR yet
    unsafe {
        IDLE.set(Box::new(Activity::new(
            kif::tilemux::IDLE_ID,
            quota::IDLE_ID,
            idle_quota,
            quota::get_pt(quota::IDLE_ID).unwrap(),
            0,
            root_pt,
        )));
        OUR.set(Box::new(Activity::new(
            kif::tilemux::ACT_ID,
            quota::IDLE_ID,
            our_quota,
            quota::get_pt(quota::IDLE_ID).unwrap(),
            0,
            root_pt,
        )));
    }

    if pex_env().tile_desc.has_virtmem() {
        let mut our_ref = our();
        our_ref.frames.push(frame);
        our_ref.init();
        our_ref.switch_to();
        paging::enable_paging();
    }
    else {
        paging::disable_paging();
    }

    // add default quota, now that initialization is done and we know how many PTs are left
    quota::add_def(quota::DEF_TIME_SLICE, PTS.borrow().len());

    BOOTSTRAP.set(false);
}

pub fn add(
    id: Id,
    bw_quota: quota::Id,
    time_quota: quota::Id,
    pt_quota: quota::Id,
    eps_start: tcu::EpId,
) -> Result<(), Error> {
    log!(crate::LOG_ACTS, "Created Activity {}", id);

    let time_quota = quota::get_time(time_quota).unwrap();
    if time_quota.total() == 0 {
        return Err(Error::new(Code::NoSpace));
    }
    time_quota.attach();

    let pt_quota = quota::get_pt(pt_quota).unwrap();
    let (frame, root_pt) = if pex_env().tile_desc.has_virtmem() {
        let (mem_tile, mem_base, _, _) = tcu::TCU::unpack_mem_ep(0).unwrap();
        let base = GlobAddr::new_with(mem_tile, mem_base);

        let frame = PTAllocator {
            act: id,
            quota: pt_quota.clone(),
        }
        .allocate_pt()?;
        (frame, Some(base + (frame - cfg::MEM_OFFSET as Phys)))
    }
    else {
        (0, None)
    };

    let mut act = Box::new(Activity::new(
        id, bw_quota, time_quota, pt_quota, eps_start, root_pt,
    ));

    if pex_env().tile_desc.has_virtmem() {
        act.frames.push(frame);
        act.init();
    }

    // safety: we obtained act from a Box
    unsafe {
        ACTIVITIES.get_mut()[id as usize] = Some(NonNull::new_unchecked(act.as_mut()));
    }

    make_blocked(act);
    Ok(())
}

pub fn get_mut(id: Id) -> Option<ActivityRef<'static>> {
    if id == kif::tilemux::ACT_ID {
        Some(our())
    }
    else {
        // safety: we check at runtime whether a reference to this activity already exists
        unsafe {
            ACTIVITIES.get_mut()[id as usize]
                .as_mut()
                .map(|v| ActivityRef::new(v.as_mut()))
        }
    }
}

pub fn our() -> ActivityRef<'static> {
    // safety: we check at runtime whether a reference to this activity already exists
    ActivityRef::new(unsafe { OUR.get_mut() })
}

pub fn idle() -> ActivityRef<'static> {
    // safety: we check at runtime whether a reference to this activity already exists
    ActivityRef::new(unsafe { IDLE.get_mut() })
}

#[allow(clippy::borrowed_box)]
pub fn try_cur() -> Option<ActivityRef<'static>> {
    // safety: we check at runtime whether a reference to this activity already exists
    unsafe { CUR.get_mut() }
        .as_mut()
        .map(|a| ActivityRef::new(a))
}

pub fn cur() -> ActivityRef<'static> {
    try_cur().unwrap()
}

pub fn has_ready() -> bool {
    !RDY.borrow().is_empty()
}

pub fn schedule(mut action: ScheduleAction) -> usize {
    let res = loop {
        let new_state = do_schedule(action);

        let mut act = cur();
        if let Some(new_act) = act.exec_cont() {
            action = new_act;
            continue;
        }

        // reset blocked state
        if act.wait_timeout {
            timer::remove(act.id());
            act.wait_timeout = false;
        }
        act.wait_ep = None;
        act.wait_irq = None;

        break new_state;
    };

    // tell the application whether there are other activities ready. if not, it can sleep via TCU without
    // telling us.
    crate::app_env().shared = has_ready() as u64;

    // disable FPU to raise an exception if the app tries to use FPU instructions
    arch::disable_fpu();

    // reprogram timer to consider budget_left of current activity
    crate::reg_timer_reprogram();

    res
}

fn do_schedule(mut action: ScheduleAction) -> usize {
    let now = TimeInstant::now();
    let mut next = RDY
        .borrow_mut()
        .pop_front()
        // safety: we know that idle is stored in a Box
        .unwrap_or_else(|| unsafe { Box::from_raw(IDLE.get_mut().as_mut()) });

    let old_time = if let Some(mut old) = try_cur() {
        // reduce budget now in case we decide not to switch below
        old.time_quota.set_left(
            old.time_quota
                .left()
                .saturating_sub((now - old.scheduled).as_nanos() as u64),
        );

        // save TCU command registers; do that first while still running with that activity
        old.cmd.save();

        // now change activity
        let old_id = tcu::TCU::xchg_activity(next.activity_reg()).unwrap();

        // are there messages left we care about?
        if action == ScheduleAction::Block && !old.can_block((old_id >> 16) as u16) {
            // if the activity has budget left (or there is no one else ready), continue with it
            if old.time_quota.left() > 0 || next.id() == kif::tilemux::IDLE_ID {
                let next_id = tcu::TCU::xchg_activity(old_id).unwrap();
                next.set_activity_reg(next_id);
                if next.id() != kif::tilemux::IDLE_ID {
                    let next_budget = TimeDuration::from_nanos(next.time_quota.left());
                    make_ready(next, next_budget);
                }
                else {
                    Box::into_raw(next);
                }
                let last_sched = old.scheduled;
                old.cpu_time += now - last_sched;
                old.scheduled = now;
                return old.user_state_addr;
            }
            // otherwise, preempt it
            else {
                action = ScheduleAction::Preempt;
            }
        }

        old.set_activity_reg(old_id);
        // pass the old budget from here to make_ready below, because we might share the budget with
        // the next activity (which prevented others from running, because we would just switch between
        // these two)
        TimeDuration::from_nanos(old.time_quota.left())
    }
    else {
        tcu::TCU::xchg_activity(next.activity_reg()).unwrap();
        TimeDuration::ZERO
    };

    // change address space
    next.switch_to();

    // set SP for the next entry
    let new_state = next.user_state_addr;
    isr::set_entry_sp(new_state + size_of::<arch::State>());
    let next_id = next.id();
    next.state = ActState::Running;

    next.scheduled = now;
    // budget is immediately refilled but we prefer other activities while a budget is 0 (see make_ready)
    if next.time_quota.left() == 0 {
        // to keep it simple, we divide the time slice by the number of users to ensure that activities
        // that share a time slice don't receive more than their share in total. the better approach
        // might be to actually schedule quotas and not activities, but that seems like overkill here.
        next.time_quota
            .set_left(next.time_quota.total() / next.time_quota.users());
    }
    let next_budget = next.time_quota.left();

    // restore TCU command registers
    next.cmd.restore();

    // exchange CUR
    // safety: we do no longer hold a reference to `own`
    if let Some(mut old) = unsafe { CUR.set(Some(next)) } {
        log!(
            crate::LOG_CTXSWS,
            "Switching from {} (budget {}) to {} (budget {}): {:?} old Activity",
            old.id(),
            old.time_quota.left(),
            next_id,
            next_budget,
            action
        );

        old.cpu_time += now - old.scheduled;
        old.ctxsws += 1;

        if old.id() != kif::tilemux::IDLE_ID {
            // block, preempt or kill activity
            match action {
                ScheduleAction::Block => {
                    make_blocked(old);
                },
                ScheduleAction::Preempt | ScheduleAction::Yield => {
                    make_ready(old, old_time);
                },
                ScheduleAction::Kill => {
                    let old_id = old.id();
                    // safety: we do not access `old` afterwards
                    unsafe {
                        ACTIVITIES.get_mut()[old_id as usize] = None;
                    }
                },
            }
        }
        else {
            old.state = ActState::Blocked;
            // don't drop the idle activity
            Box::into_raw(old);
        }
    }
    else {
        log!(
            crate::LOG_CTXSWS,
            "Switching to {} (budget {})",
            next_id,
            next_budget
        );
    }

    new_state
}

fn make_blocked(mut act: Box<Activity>) {
    act.state = ActState::Blocked;
    BLK.borrow_mut().push_back(act);
}

fn make_ready(mut act: Box<Activity>, budget: TimeDuration) {
    act.state = ActState::Ready;
    // prefer activities with budget
    if !budget.is_zero() {
        RDY.borrow_mut().push_front(act);
    }
    else {
        RDY.borrow_mut().push_back(act);
    }
}

pub fn remove_cur(status: i32) {
    let cur_id = cur().id();
    remove(cur_id, status, true, true);
}

pub fn remove(id: Id, status: i32, notify: bool, sched: bool) {
    // safety: we don't hold a reference to an activity yet
    if let Some(v) = unsafe { ACTIVITIES.get_mut()[id as usize].take() } {
        // safety: the activity reference `v` is still valid here
        let old = match unsafe { &v.as_ref().state } {
            // safety: we don't access `v` afterwards
            ActState::Running => unsafe { CUR.set(None).unwrap() },
            ActState::Ready => RDY.borrow_mut().remove_if(|v| v.id() == id).unwrap(),
            ActState::Blocked => BLK.borrow_mut().remove_if(|v| v.id() == id).unwrap(),
        };
        // we now can't access `v` anymore

        log!(
            crate::LOG_ACTS,
            "Removed Activity {} with status {}",
            old.id(),
            status
        );

        // flush+invalidate caches to ensure that we have a fresh view on memory. this is required,
        // because we expect that the pager can just map arbitrary memory and the core sees the
        // current state in DRAM. since the DRAM can change via the TCU as well, the core might have
        // cachelines that reflect an older state of the memory. for that reason, we need to flush
        // all cachelines to load everything from DRAM afterwards. note that the flush is done here,
        // because we need to make sure that it happens *before* we invalidate the PMP-EPs
        // (otherwise we cannot successfully writeback the cachelines).
        helper::flush_cache();

        if notify {
            // change to our activity (no need to save old act_reg; activity is dead)
            let pex_is_running = (tcu::TCU::get_cur_activity() & 0xFFFF) == kif::tilemux::ACT_ID;
            if !pex_is_running {
                tcu::TCU::xchg_activity(our().activity_reg()).unwrap();
            }

            let mut msg_buf = MsgBuf::borrow_def();
            base::build_vmsg!(msg_buf, kif::tilemux::Calls::EXIT, kif::tilemux::Exit {
                act_id: old.id() as tcu::ActId,
                status,
            });
            sendqueue::send(&msg_buf).unwrap();

            // switch back to old activity
            if !pex_is_running {
                let our_act = tcu::TCU::xchg_activity(old.activity_reg()).unwrap();
                our().set_activity_reg(our_act);
            }
        }

        if sched && old.state == ActState::Running {
            crate::reg_scheduling(ScheduleAction::Kill);
        }
    }
}

impl Activity {
    pub fn new(
        id: Id,
        bw_quota: kif::tilemux::QuotaId,
        time_quota: Rc<Quota<u64>>,
        pt_quota: Rc<PTQuota>,
        eps_start: tcu::EpId,
        root_pt: Option<GlobAddr>,
    ) -> Self {
        let aspace = root_pt.map(|r| {
            paging::AddrSpace::new(id, r, PTAllocator {
                act: id,
                quota: pt_quota,
            })
        });

        Activity {
            prev: None,
            next: None,
            aspace,
            frames: Vec::new(),
            act_reg: id | ((bw_quota as u64) << 32),
            state: ActState::Blocked,
            #[cfg(any(target_arch = "riscv64", target_arch = "x86_64"))]
            fpu_state: arch::FPUState::default(),
            user_state: arch::State::default(),
            user_state_addr: 0,
            time_quota,
            cpu_time: TimeDuration::ZERO,
            ctxsws: 0,
            scheduled: TimeInstant::now(),
            wait_timeout: false,
            wait_irq: None,
            wait_ep: None,
            irq_mask: 0,
            eps_start,
            cmd: helper::TCUCmdState::new(),
            pf_state: None,
            cont: None,
            has_refs: false,
        }
    }

    pub fn map(
        &mut self,
        virt: usize,
        global: GlobAddr,
        pages: usize,
        perm: kif::PageFlags,
    ) -> Result<(), Error> {
        self.aspace
            .as_mut()
            .unwrap()
            .map_pages(virt, global, pages, perm)
    }

    pub fn translate(&self, virt: usize, perm: kif::PageFlags) -> kif::PTE {
        self.aspace.as_ref().unwrap().translate(virt, perm.bits())
    }

    pub fn id(&self) -> Id {
        self.act_reg & 0xFFFF
    }

    pub fn state(&self) -> ActState {
        self.state
    }

    pub fn activity_reg(&self) -> tcu::Reg {
        self.act_reg
    }

    pub fn set_activity_reg(&mut self, val: tcu::Reg) {
        self.act_reg = val;
    }

    #[cfg(any(target_arch = "riscv64", target_arch = "x86_64"))]
    pub fn fpu_state(&mut self) -> &mut arch::FPUState {
        &mut self.fpu_state
    }

    pub fn eps_start(&self) -> tcu::EpId {
        self.eps_start
    }

    pub fn msgs(&self) -> u16 {
        (self.act_reg >> 16) as u16
    }

    pub fn has_msgs(&self) -> bool {
        self.msgs() != 0
    }

    pub fn add_msg(&mut self) {
        self.act_reg += 1 << 16;
    }

    pub fn rem_msgs(&mut self, count: u16) {
        assert!(self.msgs() >= count);
        self.act_reg -= (count as u64) << 16;
    }

    pub fn budget_left(&self) -> TimeDuration {
        TimeDuration::from_nanos(self.time_quota.left())
    }

    pub fn user_state(&mut self) -> &mut arch::State {
        &mut self.user_state
    }

    pub fn reset_stats(&mut self) -> TimeDuration {
        let now = TimeInstant::now();
        let old_time = if self.state == ActState::Running {
            self.cpu_time + (now - self.scheduled)
        }
        else {
            self.cpu_time
        };
        log!(
            crate::LOG_ACTS,
            "Activity{} consumed {:?} CPU time and was suspended {} times",
            self.id(),
            old_time,
            self.ctxsws
        );
        self.scheduled = now;
        self.cpu_time = TimeDuration::ZERO;
        self.ctxsws = 0;
        old_time
    }

    pub fn irq_mask(&self) -> u32 {
        self.irq_mask
    }

    pub fn add_irq(&mut self, irq: u32) {
        self.irq_mask |= 1 << irq;
    }

    fn can_block(&self, msgs: u16) -> bool {
        if let Some(wep) = self.wait_ep {
            !tcu::TCU::has_msgs(wep)
        }
        else {
            msgs == 0
        }
    }

    pub fn block(
        &mut self,
        cont: Option<fn(&mut Activity) -> ContResult>,
        ep: Option<tcu::EpId>,
        irq: Option<tmif::IRQId>,
        timeout: Option<TimeDuration>,
    ) {
        log!(
            crate::LOG_CTXSWS,
            "Block Activity {} for ep={:?}, irq={:?}, timeout={:?}",
            self.id(),
            ep,
            irq,
            timeout,
        );

        self.cont = cont;
        self.wait_ep = ep;
        self.wait_irq = irq;
        self.wait_timeout = timeout.is_some();

        if self.state == ActState::Running {
            crate::reg_scheduling(ScheduleAction::Block);
        }
    }

    fn should_unblock(&self, event: &Event) -> bool {
        match event {
            Event::Message(eep) => match self.wait_ep {
                // if we wait for a specific EP, only unblock if this EP got a message
                Some(wep) => *eep == wep,
                // if we wait for a specific IRQ, don't unblock on messages
                None => self.wait_irq.is_none(),
            },
            Event::Interrupt(eirq) => match self.wait_irq {
                // if we wait for a specific IRQ, only unblock if this IRQ occurred
                Some(wirq) => *eirq == wirq,
                // if we wait for a specific EP, don't unblock on IRQs
                None => self.wait_ep.is_none(),
            },
            // always unblock on timeouts or invalided EPs
            Event::Timeout => true,
            Event::EpInvalid => true,
            Event::Start => true,
        }
    }

    pub fn unblock(&mut self, event: Event) -> bool {
        log!(
            crate::LOG_CTXSWS,
            "Trying to unblock Activity {} for event={:?}",
            self.id(),
            event
        );

        // activity not ready yet?
        if self.user_state_addr == 0 {
            return false;
        }

        if !self.should_unblock(&event) {
            return false;
        }

        if self.state == ActState::Blocked {
            let mut act = BLK.borrow_mut().remove_if(|v| v.id() == self.id()).unwrap();
            if !matches!(event, Event::Timeout) && act.wait_timeout {
                timer::remove(act.id());
                act.wait_timeout = false;
            }
            let budget = TimeDuration::from_nanos(act.time_quota.left());
            make_ready(act, budget);
        }
        if self.state != ActState::Running {
            crate::reg_scheduling(ScheduleAction::Yield);
        }
        true
    }

    pub fn consume_time(&mut self) {
        let now = TimeInstant::now();
        let duration = now - self.scheduled;
        self.time_quota.set_left(
            self.time_quota
                .left()
                .saturating_sub(duration.as_nanos() as u64),
        );
        if self.time_quota.left() == 0 && has_ready() {
            crate::reg_scheduling(ScheduleAction::Preempt);
        }
    }

    pub fn start_pf(&mut self, pf_state: PfState) {
        self.pf_state = Some(pf_state);
    }

    pub fn finish_pf(&mut self) -> PfState {
        self.pf_state.take().unwrap()
    }

    pub fn start(&mut self) {
        assert!(self.user_state_addr == 0);
        // ensure that recent page table modifications (initialization of the AS) are considered
        if let Some(ref aspace) = self.aspace {
            aspace.flush_tlb();
        }
        // remember the current tile and platform
        crate::app_env().tile_id = pex_env().tile_id;
        crate::app_env().platform = pex_env().platform;
        if self.id() != kif::tilemux::IDLE_ID {
            arch::init_state(
                &mut self.user_state,
                crate::app_env().entry as usize,
                crate::app_env().sp as usize,
            );
        }
        self.user_state_addr = &self.user_state as *const _ as usize;
    }

    pub fn switch_to(&self) {
        if let Some(ref aspace) = self.aspace {
            aspace.switch_to();
        }
    }

    fn exec_cont(&mut self) -> Option<ScheduleAction> {
        self.cont.take().and_then(|cont| {
            let result = cont(self);
            match result {
                // only resume this activity if it has been initialized
                ContResult::Success if self.user_state_addr != 0 => None,
                // not initialized yet
                ContResult::Success => Some(ScheduleAction::Block),
                // failed, so remove activity
                ContResult::Failure => {
                    remove(self.id(), 1, true, false);
                    Some(ScheduleAction::Kill)
                },
                // set the continuation again to retry later
                ContResult::Waiting => {
                    self.cont = Some(cont);
                    // we might have got the PF reply after checking for it, so use TryBlock to not
                    // schedule in case we've received a message.
                    Some(ScheduleAction::Block)
                },
            }
        })
    }

    fn init(&mut self) {
        extern "C" {
            static _user_start: u8;
            static _user_end: u8;
            static _text_start: u8;
            static _text_end: u8;
            static _data_start: u8;
            static _data_end: u8;
            static _bss_start: u8;
            static _bss_end: u8;
        }

        let (mem_tile, mem_base, mem_size, _) = tcu::TCU::unpack_mem_ep(0).unwrap();
        let base = GlobAddr::new_with(mem_tile, mem_base);

        // we have to perform the initialization here, because it calls xlate_pt(), so that the activity
        // needs to be accessible via get_mut().
        self.aspace.as_mut().unwrap().init();

        // map TCU
        let rw = kif::PageFlags::RW;
        self.map(
            tcu::MMIO_ADDR,
            GlobAddr::new(tcu::MMIO_ADDR as goff),
            tcu::MMIO_SIZE / cfg::PAGE_SIZE,
            kif::PageFlags::U | rw,
        )
        .unwrap();
        self.map(
            tcu::MMIO_PRIV_ADDR,
            GlobAddr::new(tcu::MMIO_PRIV_ADDR as goff),
            tcu::MMIO_PRIV_SIZE / cfg::PAGE_SIZE,
            kif::PageFlags::U | rw,
        )
        .unwrap();

        // map text, data, and bss
        let rx = kif::PageFlags::RX;
        unsafe {
            self.map_segment(base, &_text_start, &_text_end, rx);
            self.map_segment(base, &_data_start, &_data_end, rw);
            self.map_segment(base, &_bss_start, &_bss_end, rw);
            // ensure that the receive buffer does not overlap with text, data, and bss
            assert!(cfg::TILEMUX_RBUF_SPACE >= &_bss_end as *const u8 as usize);
        }

        // map own receive buffer
        let own_rbuf = base + (cfg::TILEMUX_RBUF_SPACE - cfg::MEM_OFFSET) as goff;
        assert!(cfg::TILEMUX_RBUF_SIZE == cfg::PAGE_SIZE);
        self.map(cfg::TILEMUX_RBUF_SPACE, own_rbuf, 1, kif::PageFlags::R)
            .unwrap();

        if self.id() == kif::tilemux::ACT_ID {
            // map sleep function for user
            unsafe {
                self.map_segment(base, &_user_start, &_user_end, rx | kif::PageFlags::U);
            }
        }
        else {
            // map application receive buffer
            let perm = kif::PageFlags::R | kif::PageFlags::U;
            self.map_new_mem(base, cfg::RBUF_STD_ADDR, cfg::RBUF_STD_SIZE, perm);
        }

        // map runtime environment
        self.map_new_mem(
            base,
            cfg::ENV_START & !cfg::PAGE_MASK,
            cfg::ENV_SIZE,
            rw | kif::PageFlags::U,
        );

        // map PTs
        self.map(
            cfg::TILE_MEM_BASE,
            base,
            mem_size as usize / cfg::PAGE_SIZE,
            rw,
        )
        .unwrap();

        // map PLIC
        #[cfg(target_vendor = "hw")]
        {
            self.map(0x0C00_0000, GlobAddr::new(0x0C00_0000), 1, rw)
                .unwrap();
            self.map(0x0C00_2000, GlobAddr::new(0x0C00_2000), 1, rw)
                .unwrap();
            self.map(0x0C20_0000, GlobAddr::new(0x0C20_0000), 1, rw)
                .unwrap();
        }

        // map vectors
        #[cfg(target_arch = "arm")]
        self.map(0, base, 1, rx).unwrap();

        // insert fixed entry for messages into TLB
        let virt = MsgBuf::borrow_def().bytes().as_ptr() as usize;
        let pte = self.translate(virt, kif::PageFlags::R);
        let phys = pte & !(cfg::PAGE_MASK as u64);
        let mut flags = kif::PageFlags::from_bits_truncate(pte & cfg::PAGE_MASK as u64);
        flags |= kif::PageFlags::FIXED;
        tcu::TCU::insert_tlb(self.id() as u16, virt, phys, flags).unwrap();
    }

    fn map_new_mem(&mut self, base: GlobAddr, addr: usize, size: usize, perm: kif::PageFlags) {
        for i in 0..(size / cfg::PAGE_SIZE) {
            let frame = self
                .aspace
                .as_mut()
                .unwrap()
                .allocator_mut()
                .allocate_pt()
                .unwrap();

            self.frames.push(frame);
            self.map(
                addr + i * cfg::PAGE_SIZE,
                base + (frame - cfg::MEM_OFFSET as Phys),
                1,
                perm,
            )
            .unwrap();
        }
    }

    fn map_segment(
        &mut self,
        base: GlobAddr,
        start: *const u8,
        end: *const u8,
        perm: kif::PageFlags,
    ) {
        let start = math::round_dn(start as usize, cfg::PAGE_SIZE);
        let end = math::round_up(end as usize, cfg::PAGE_SIZE);
        let pages = (end - start) / cfg::PAGE_SIZE;
        let glob = base + (start - cfg::MEM_OFFSET) as Phys;
        self.map(start, glob, pages, perm).unwrap();
    }
}

impl Drop for Activity {
    fn drop(&mut self) {
        if self.state == ActState::Running {
            let now = TimeInstant::now();
            self.cpu_time += now - self.scheduled;
        }

        log!(
            crate::LOG_ACTS,
            "Destroyed Activity {} ({:?} CPU time, {} context switches)",
            self.id(),
            self.cpu_time,
            self.ctxsws,
        );

        if let Some(ref mut aspace) = self.aspace {
            // free frames we allocated for env, receive buffers etc.
            for f in &self.frames {
                aspace.allocator_mut().free_pt(*f as paging::MMUPTE);
            }
        }

        // remove activity from other modules
        self.time_quota.detach();
        if self.wait_timeout {
            timer::remove(self.id());
        }
        irqs::remove(self);
        arch::forget_fpu(self.id());
    }
}
