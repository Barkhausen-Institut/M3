/*
 * Copyright (C) 2022 Nils Asmussen, Barkhausen Institut
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
use base::io::LogFlags;
use base::kif;
use base::log;
use base::mem::{GlobAddr, GlobAddrRaw, VirtAddr};
use base::tcu::{EpId, INVALID_EP, IRQ};
use base::time::TimeDuration;
use base::tmif;

use isr::{ISRArch, ISR};

use crate::activities;
use crate::irqs;
use crate::timer;
use crate::vma;
use crate::{arch, helper};

fn tmcall_wait(state: &mut arch::State) -> Result<(), Error> {
    let ep = state.r[isr::TMC_ARG1] as EpId;
    let irq = state.r[isr::TMC_ARG2] as tmif::IRQId;
    let timeout = match state.r[isr::TMC_ARG3] {
        usize::MAX => None,
        t => Some(TimeDuration::from_nanos(t as u64)),
    };

    log!(
        LogFlags::MuxCalls,
        "tmcall::wait(ep={}, irq={}, timeout={:?})",
        ep,
        irq,
        timeout,
    );

    let mut cur = activities::cur();
    let wait_ep = if ep == INVALID_EP { None } else { Some(ep) };
    let wait_irq = if irq <= IRQ::Timer as tmif::IRQId || irq == tmif::INVALID_IRQ {
        None
    }
    else {
        Some(irq)
    };

    if (wait_ep.is_none() || wait_irq.is_some()) && irqs::wait(&cur, wait_irq).is_some() {
        return Ok(());
    }

    if let Some(t) = timeout {
        timer::add(cur.id(), t);
    }
    cur.block(None, wait_ep, wait_irq, timeout);

    Ok(())
}

fn tmcall_stop(state: &mut arch::State) -> Result<(), Error> {
    let code = Code::from(state.r[isr::TMC_ARG1] as u32);

    log!(LogFlags::MuxCalls, "tmcall::stop(code={:?})", code);

    activities::remove_cur(code);

    Ok(())
}

fn tmcall_yield(_state: &mut arch::State) -> Result<(), Error> {
    log!(LogFlags::MuxCalls, "tmcall::yield()");

    if activities::has_ready() {
        crate::reg_scheduling(activities::ScheduleAction::Yield);
    }
    Ok(())
}

fn tmcall_map(state: &mut arch::State) -> Result<(), Error> {
    let virt = VirtAddr::from(state.r[isr::TMC_ARG1]);
    let glob = GlobAddr::new(state.r[isr::TMC_ARG2] as GlobAddrRaw);
    let pages = state.r[isr::TMC_ARG3];
    let access = kif::Perm::from_bits_truncate(state.r[isr::TMC_ARG4] as u32);
    let flags = kif::PageFlags::from(access) & kif::PageFlags::RW;

    log!(
        LogFlags::MuxCalls,
        "tmcall::map(virt={}, glob={}, pages={}, access={:?})",
        virt,
        glob,
        pages,
        access
    );

    if pages == 0 || flags.is_empty() {
        return Err(Error::new(Code::InvArgs));
    }

    // TODO validate virtual and global address

    activities::cur().map(virt, glob, pages, flags | kif::PageFlags::U)
}

fn tmcall_reg_irq(state: &mut arch::State) -> Result<(), Error> {
    let irq = state.r[isr::TMC_ARG1] as tmif::IRQId;

    log!(LogFlags::MuxCalls, "tmcall::reg_irq(irq={:?})", irq);

    // TODO validate whether the activity is allowed to use these IRQs

    irqs::register(&mut activities::cur(), irq);

    Ok(())
}

fn tmcall_transl_fault(state: &mut arch::State) -> Result<(), Error> {
    let virt = VirtAddr::from(state.r[isr::TMC_ARG1]);
    let access = kif::Perm::from_bits_truncate(state.r[isr::TMC_ARG2] as u32);
    let flags = kif::PageFlags::from(access) & kif::PageFlags::RW;

    log!(
        LogFlags::MuxCalls,
        "tmcall::transl_fault(virt={}, access={:?})",
        virt,
        access
    );

    vma::handle_xlate(virt, flags);

    Ok(())
}

fn tmcall_init_tls(state: &mut arch::State) -> Result<(), Error> {
    let virt = VirtAddr::from(state.r[isr::TMC_ARG1]);

    log!(LogFlags::MuxCalls, "tmcall::tmcall_init_tls(virt={})", virt);

    ISR::init_tls(virt);

    Ok(())
}

fn tmcall_flush_inv(_state: &mut arch::State) -> Result<(), Error> {
    log!(LogFlags::MuxCalls, "tmcall::flush_inv()");

    helper::flush_cache();

    Ok(())
}

fn tmcall_noop(_state: &mut arch::State) -> Result<(), Error> {
    log!(LogFlags::MuxCalls, "tmcall::noop()");

    Ok(())
}

pub fn handle_call(state: &mut arch::State) {
    let opcode = state.r[isr::TMC_ARG0];

    let res = match opcode {
        o if o == tmif::Operation::Wait.into() => tmcall_wait(state),
        o if o == tmif::Operation::Exit.into() => tmcall_stop(state),
        o if o == tmif::Operation::Yield.into() => tmcall_yield(state),
        o if o == tmif::Operation::Map.into() => tmcall_map(state),
        o if o == tmif::Operation::RegIRQ.into() => tmcall_reg_irq(state),
        o if o == tmif::Operation::TranslFault.into() => tmcall_transl_fault(state),
        o if o == tmif::Operation::InitTLS.into() => tmcall_init_tls(state),
        o if o == tmif::Operation::FlushInv.into() => tmcall_flush_inv(state),
        o if o == tmif::Operation::Noop.into() => tmcall_noop(state),
        _ => Err(Error::new(Code::InvArgs)),
    };

    if let Err(e) = &res {
        log!(
            LogFlags::MuxCalls,
            "\x1B[1mError for call {:?}: {:?}\x1B[0m",
            tmif::Operation::try_from(opcode),
            e.code()
        );
    }

    state.r[isr::TMC_ARG0] = match res {
        Ok(_) => 0,
        Err(e) => e.code() as usize,
    };
}
