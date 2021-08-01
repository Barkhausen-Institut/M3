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

use base::errors::{Code, Error};
use base::goff;
use base::kif;
use base::log;
use base::mem::GlobAddr;
use base::pexif;
use base::tcu::{EpId, INVALID_EP};

use crate::irqs;
use crate::timer::Nanos;
use crate::vma;
use crate::vpe;
use crate::{arch, helper};

fn pexcall_sleep(state: &mut arch::State) -> Result<(), Error> {
    let dur = state.r[isr::PEXC_ARG1] as Nanos;
    let ep = state.r[isr::PEXC_ARG2] as EpId;

    log!(crate::LOG_CALLS, "pexcall::sleep(dur={}, ep={})", dur, ep);

    let wait_event = if ep == INVALID_EP {
        None
    }
    else {
        Some(vpe::Event::Message(ep))
    };
    let sleep = if dur == 0 { None } else { Some(dur) };

    vpe::cur().block(None, wait_event, sleep);

    Ok(())
}

fn pexcall_stop(state: &mut arch::State) -> Result<(), Error> {
    let code = state.r[isr::PEXC_ARG1] as u32;

    log!(crate::LOG_CALLS, "pexcall::stop(code={})", code);

    vpe::remove_cur(code);

    Ok(())
}

fn pexcall_yield(_state: &mut arch::State) -> Result<(), Error> {
    log!(crate::LOG_CALLS, "pexcall::yield()");

    if vpe::has_ready() {
        crate::reg_scheduling(vpe::ScheduleAction::Yield);
    }
    Ok(())
}

fn pexcall_map(state: &mut arch::State) -> Result<(), Error> {
    let virt = state.r[isr::PEXC_ARG1] as usize;
    let phys = state.r[isr::PEXC_ARG2] as goff;
    let pages = state.r[isr::PEXC_ARG3] as usize;
    let access = kif::Perm::from_bits_truncate(state.r[isr::PEXC_ARG4] as u32);
    let flags = kif::PageFlags::from(access) & kif::PageFlags::RW;

    log!(
        crate::LOG_CALLS,
        "pexcall::map(virt={:#x}, phys={:#x}, pages={}, access={:?})",
        virt,
        phys,
        pages,
        access
    );

    if pages == 0 || flags.is_empty() {
        return Err(Error::new(Code::InvArgs));
    }

    // TODO validate virtual and physical address

    let global = GlobAddr::new(phys);
    vpe::cur().map(virt, global, pages, flags | kif::PageFlags::U)
}

fn pexcall_wait_irq(state: &mut arch::State) -> Result<(), Error> {
    let irqs = state.r[isr::PEXC_ARG1] as u32;
    let timeout_ns = state.r[isr::PEXC_ARG2] as u64;

    log!(
        crate::LOG_CALLS,
        "pexcall::wait_irq(irqs={:#x}, timeout_ns={})",
        irqs,
        timeout_ns
    );

    // TODO validate whether the VPE is allowed to use these IRQs

    let timeout = if timeout_ns == 0 {
        None
    }
    else {
        Some(timeout_ns)
    };
    irqs::wait(vpe::cur().id(), irqs, timeout);

    Ok(())
}

fn pexcall_transl_fault(state: &mut arch::State) -> Result<(), Error> {
    let virt = state.r[isr::PEXC_ARG1] as usize;
    let access = kif::Perm::from_bits_truncate(state.r[isr::PEXC_ARG2] as u32);
    let flags = kif::PageFlags::from(access) & kif::PageFlags::RW;

    log!(
        crate::LOG_CALLS,
        "pexcall::transl_fault(virt={:#x}, access={:?})",
        virt,
        access
    );

    vma::handle_xlate(virt, flags);

    Ok(())
}

fn pexcall_flush_inv(_state: &mut arch::State) -> Result<(), Error> {
    log!(crate::LOG_CALLS, "pexcall::flush_inv()");

    helper::flush_invalidate();

    Ok(())
}

fn pexcall_noop(_state: &mut arch::State) -> Result<(), Error> {
    log!(crate::LOG_CALLS, "pexcall::noop()");

    Ok(())
}

pub fn handle_call(state: &mut arch::State) {
    let call = pexif::Operation::from(state.r[isr::PEXC_ARG0] as isize);

    let res = match call {
        pexif::Operation::SLEEP => pexcall_sleep(state).map(|_| 0isize),
        pexif::Operation::EXIT => pexcall_stop(state).map(|_| 0isize),
        pexif::Operation::YIELD => pexcall_yield(state).map(|_| 0isize),
        pexif::Operation::MAP => pexcall_map(state).map(|_| 0isize),
        pexif::Operation::WAIT_IRQ => pexcall_wait_irq(state).map(|_| 0isize),
        pexif::Operation::TRANSL_FAULT => pexcall_transl_fault(state).map(|_| 0isize),
        pexif::Operation::FLUSH_INV => pexcall_flush_inv(state).map(|_| 0isize),
        pexif::Operation::NOOP => pexcall_noop(state).map(|_| 0isize),

        _ => Err(Error::new(Code::NotSup)),
    };

    if let Err(e) = &res {
        log!(
            crate::LOG_CALLS,
            "\x1B[1mError for call {:?}: {:?}\x1B[0m",
            call,
            e.code()
        );
    }

    state.r[isr::PEXC_ARG0] = res.unwrap_or_else(|e| -(e.code() as isize)) as usize;
}
