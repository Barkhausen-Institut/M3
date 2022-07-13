/*
 * Copyright (C) 2021-2022 Nils Asmussen, Barkhausen Institut
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

use base::cell::Cell;
use base::cell::StaticCell;
use base::cell::StaticRefCell;
use base::col::Vec;
use base::errors::{Code, Error};
use base::kif;
use base::log;
use base::rc::Rc;
use base::time::TimeDuration;

use core::fmt;

use num_traits::PrimInt;

pub type Id = kif::tilemux::QuotaId;

pub const IDLE_ID: Id = kif::tilemux::IDLE_QUOTA_ID;

pub const DEF_TIME_SLICE: TimeDuration = TimeDuration::from_millis(1);

pub struct Quota<T> {
    id: Id,
    parent: Option<Id>,
    users: Cell<u64>,
    total: Cell<T>,
    left: Cell<T>,
}

impl<T: PrimInt + fmt::Display> Quota<T> {
    pub fn new(id: Id, parent: Option<Id>, amount: T) -> Rc<Self> {
        Rc::new(Self {
            id,
            parent,
            users: Cell::from(0),
            total: Cell::from(amount),
            left: Cell::from(amount),
        })
    }

    fn derive(&self, amount: T) -> Result<Rc<Self>, Error> {
        NEXT_ID.set(NEXT_ID.get() + 1);
        Ok(Self::new(NEXT_ID.get() - 1, Some(self.id), amount))
    }

    pub fn id(&self) -> Id {
        self.id
    }

    pub fn users(&self) -> u64 {
        self.users.get()
    }

    pub fn attach(&self) {
        self.users.set(self.users.get() + 1);
    }

    pub fn detach(&self) {
        self.users.set(self.users.get() - 1);
    }

    pub fn total(&self) -> T {
        self.total.get()
    }

    pub fn set_total(&self, val: T) {
        self.total.set(val);
    }

    pub fn left(&self) -> T {
        self.left.get()
    }

    pub fn set_left(&self, val: T) {
        self.left.set(val);
    }
}

impl<T: fmt::Display + Copy> fmt::Debug for Quota<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Q[{}: {} of {}, users={}, parent={:?}]",
            self.id,
            self.left.get(),
            self.total.get(),
            self.users.get(),
            self.parent
        )
    }
}

pub type TimeQuota = Quota<u64>;
pub type PTQuota = Quota<usize>;

static NEXT_ID: StaticCell<Id> = StaticCell::new(0);
static TIME_QUOTAS: StaticRefCell<Vec<Rc<TimeQuota>>> = StaticRefCell::new(Vec::new());
static PT_QUOTAS: StaticRefCell<Vec<Rc<PTQuota>>> = StaticRefCell::new(Vec::new());

pub fn get_time(id: Id) -> Option<Rc<TimeQuota>> {
    TIME_QUOTAS.borrow().iter().find(|q| q.id == id).cloned()
}

pub fn get_pt(id: Id) -> Option<Rc<PTQuota>> {
    PT_QUOTAS.borrow().iter().find(|q| q.id == id).cloned()
}

pub fn init(pts: usize) {
    // for idle and ourself
    TIME_QUOTAS.borrow_mut().push(TimeQuota::new(
        IDLE_ID,
        None,
        DEF_TIME_SLICE.as_nanos() as u64,
    ));
    PT_QUOTAS
        .borrow_mut()
        .push(PTQuota::new(IDLE_ID, None, pts));
}

pub fn add_def(time: TimeDuration, pts: usize) {
    // for all other activities
    let id = kif::tilemux::DEF_QUOTA_ID;
    TIME_QUOTAS
        .borrow_mut()
        .push(TimeQuota::new(id, None, time.as_nanos() as u64));
    PT_QUOTAS.borrow_mut().push(PTQuota::new(id, None, pts));
    NEXT_ID.set(2);
}

pub fn get(time: Id, pts: Id) -> Result<(u64, u64, usize, usize), Error> {
    let ptime = get_time(time).ok_or_else(|| Error::new(Code::InvArgs))?;
    let ppt = get_pt(pts).ok_or_else(|| Error::new(Code::InvArgs))?;

    Ok((ptime.total(), ptime.left(), ppt.total(), ppt.left()))
}

pub fn set(id: Id, time: TimeDuration, pts: usize) -> Result<(), Error> {
    let ptime = get_time(id).ok_or_else(|| Error::new(Code::InvArgs))?;
    let ppt = get_pt(id).ok_or_else(|| Error::new(Code::InvArgs))?;

    log!(
        crate::LOG_QUOTAS,
        "quota::set(id={}, time={}, ppt={})",
        id,
        time.as_nanos(),
        pts
    );

    ptime.total.set(time.as_nanos() as u64);
    ptime.left.set(time.as_nanos() as u64);
    log!(crate::LOG_QUOTAS, "time-quota: {:?}", ptime);

    if pts > ppt.total() {
        ppt.left.set(ppt.left() + (pts - ppt.total()));
    }
    else {
        ppt.left.set(ppt.left() - (ppt.total() - pts));
    }
    ppt.total.set(pts);
    log!(crate::LOG_QUOTAS, "pt-quota: {:?}", ppt);

    Ok(())
}

pub fn derive(
    parent_time: Id,
    parent_pts: Id,
    time: Option<TimeDuration>,
    pts: Option<usize>,
) -> Result<(Id, Id), Error> {
    let ptime = get_time(parent_time).ok_or_else(|| Error::new(Code::InvArgs))?;
    let ppt = get_pt(parent_pts).ok_or_else(|| Error::new(Code::InvArgs))?;

    log!(
        crate::LOG_QUOTAS,
        "quota::derive(ptime={}, ppt={}, time={:?}, pts={:?})",
        parent_time,
        parent_pts,
        time,
        pts
    );

    let time_id = if let Some(t) = time {
        let total = TimeDuration::from_nanos(ptime.total());
        if total < t {
            return Err(Error::new(Code::NoSpace));
        }
        if ptime.users() > 0 && total == t {
            return Err(Error::new(Code::InvArgs));
        }

        ptime.set_total((total - t).as_nanos() as u64);
        ptime.set_left(ptime.left().saturating_sub(t.as_nanos() as u64));

        let ctime = ptime.derive(t.as_nanos() as u64)?;
        log!(
            crate::LOG_QUOTAS,
            "time-quota: parent={:?}, child={:?}",
            ptime,
            ctime
        );
        TIME_QUOTAS.borrow_mut().push(ctime.clone());
        ctime.id
    }
    else {
        ptime.id
    };

    let pt_id = if let Some(p) = pts {
        if ppt.left() < p {
            return Err(Error::new(Code::NoSpace));
        }

        ppt.set_total(ppt.total() - p);
        ppt.set_left(ppt.left() - p);

        let cpt = ppt.derive(p)?;
        log!(
            crate::LOG_QUOTAS,
            "pt-quota: parent={:?}, child={:?}",
            ppt,
            cpt
        );
        PT_QUOTAS.borrow_mut().push(cpt.clone());
        cpt.id
    }
    else {
        ppt.id
    };

    Ok((time_id, pt_id))
}

pub fn remove(time: Option<Id>, pts: Option<Id>) -> Result<(), Error> {
    log!(
        crate::LOG_QUOTAS,
        "quota::remove(time={:?}, pt={:?})",
        time,
        pts
    );

    if let Some(id) = time {
        assert!(id > kif::tilemux::DEF_QUOTA_ID);
        let time = get_time(id).ok_or_else(|| Error::new(Code::InvArgs))?;
        log!(crate::LOG_QUOTAS, "time-quota: removing {:?}", time);
        // give quota back to parent object
        if let Some(parent) = time.parent {
            let ptime = get_time(parent).unwrap();
            ptime.set_total(ptime.total() + time.total());
        }
        TIME_QUOTAS.borrow_mut().retain(|q| q.id != id);
    }

    if let Some(id) = pts {
        assert!(id > kif::tilemux::DEF_QUOTA_ID);
        let pt = get_pt(id).ok_or_else(|| Error::new(Code::InvArgs))?;
        log!(crate::LOG_QUOTAS, "pt-quota: removing {:?}", pt);
        if let Some(parent) = pt.parent {
            assert!(pt.left == pt.total);
            let ppt = get_pt(parent).unwrap();
            ppt.set_left(ppt.left() + pt.total());
            ppt.set_total(ppt.total() + pt.total());
        }
        PT_QUOTAS.borrow_mut().retain(|q| q.id != id);
    }

    Ok(())
}
