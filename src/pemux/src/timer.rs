/*
 * Copyright (C) 2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
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

use base::cell::StaticRefCell;
use base::col::Vec;
use base::kif;
use base::log;
use base::tcu;
use base::time::{TimeDuration, TimeInstant};
use core::cmp;

use crate::vpe;

struct Timeout {
    end: TimeInstant,
    vpe: vpe::Id,
}

static LIST: StaticRefCell<Vec<Timeout>> = StaticRefCell::new(Vec::new());

pub fn add(vpe: vpe::Id, duration: TimeDuration) {
    let timeout = Timeout {
        end: TimeInstant::now() + duration,
        vpe,
    };

    log!(
        crate::LOG_TIMER,
        "timer: blocking VPE {} for {} ns (until {:?})",
        vpe,
        duration.as_nanos(),
        timeout.end
    );

    // insert new timeout in descending order of timeouts
    let mut list = LIST.borrow_mut();
    if let Some(idx) = list.iter().position(|t| t.end < timeout.end) {
        list.insert(idx, timeout);
    }
    else {
        list.push(timeout);
        drop(list);
        reprogram();
    }
}

pub fn remove(vpe: vpe::Id) {
    log!(crate::LOG_TIMER, "timer: removing VPE {}", vpe);
    LIST.borrow_mut().retain(|t| t.vpe != vpe);
    reprogram();
}

pub fn reprogram() {
    // determine the remaining budget of the current VPE, if there is any
    let budget = vpe::try_cur().and_then(|cur| {
        // don't use a budget if there is no ready VPE or we're idling
        if vpe::has_ready() && cur.id() != kif::pemux::IDLE_ID {
            Some(cur.budget_left())
        }
        else {
            None
        }
    });

    // determine timeout to program
    let list = LIST.borrow();
    let timeout = match (list.is_empty(), budget) {
        // no timeout programmed: use the budget
        (true, Some(b)) => b,
        // no timeout and no budget: disable timer
        (true, None) => TimeDuration::ZERO,
        // timeout: program the earlier point in time
        (false, _) => {
            let now = TimeInstant::now();
            let next_timeout = list[list.len() - 1].end;
            // if the timeout is in the future, program the timer for the difference
            let timeout = if next_timeout > now {
                next_timeout - now
            }
            // otherwise, program the timer for "the earliest point in time in the future"
            else {
                TimeDuration::from_nanos(1)
            };
            cmp::min(timeout, budget.unwrap_or(TimeDuration::MAX))
        },
    };

    log!(crate::LOG_TIMER, "timer: setting timer to {:?}", timeout);
    tcu::TCU::set_timer(timeout.as_nanos() as u64).unwrap();
}

pub fn trigger() {
    let mut list = LIST.borrow_mut();
    if list.is_empty() {
        return;
    }

    // unblock all VPEs whose timeouts are due
    let now = TimeInstant::now();
    while !list.is_empty() && now >= list[list.len() - 1].end {
        let timeout = list.pop().unwrap();
        log!(
            crate::LOG_TIMER,
            "timer: unblocking VPE {} @ {:?}",
            timeout.vpe,
            now
        );
        vpe::get_mut(timeout.vpe)
            .unwrap()
            .unblock(vpe::Event::Timeout);
    }
    drop(list);

    // if a scheduling is pending, we can skip this step here, because we'll do it later anyway
    if !crate::scheduling_pending() {
        reprogram();
    }
}
