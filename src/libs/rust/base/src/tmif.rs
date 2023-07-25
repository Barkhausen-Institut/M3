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

//! Contains the interface between applications and TileMux

use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::errors::{Code, Error};
use crate::kif;
use crate::mem::{PhysAddr, VirtAddr};
use crate::tcu::EpId;
use crate::time::TimeDuration;

use cfg_if::cfg_if;

pub type IRQId = u32;

pub const INVALID_IRQ: IRQId = !0;

/// The operations TileMux supports
#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[repr(usize)]
pub enum Operation {
    /// Wait for an event, optionally with timeout
    Wait,
    /// Exit the application
    Exit,
    /// Switch to the next ready activity
    Yield,
    /// Map local physical memory (IO memory)
    Map,
    /// Register for a given interrupt
    RegIRQ,
    /// For TCU TLB misses
    TranslFault,
    /// Flush and invalidate cache
    FlushInv,
    /// Initializes thread-local storage (x86 only)
    InitTLS,
    /// Noop operation for testing purposes
    Noop,
    ActInfo,
}

pub(crate) fn get_result(res: usize) -> Result<(), Error> {
    Result::from(Code::from(res as u32))
}

cfg_if! {
    if #[cfg(feature = "linux")] {
        use libc;
        use std::ptr;

        #[inline(always)]
        pub fn wait(
            ep: Option<EpId>,
            irq: Option<IRQId>,
            duration: Option<TimeDuration>,
        ) -> Result<(), Error> {
            if ep.is_some() || irq.is_some() {
                return Err(Error::new(Code::NotSup));
            }

            if let Some(dur) = duration {
                let time = libc::timespec {
                    tv_sec: dur.as_secs() as i64,
                    tv_nsec: (dur.as_nanos() - dur.as_secs() as u128 * 1_000_000_000) as i64,
                };
                unsafe {
                    libc::nanosleep(&time, ptr::null_mut());
                }
            }
            Ok(())
        }

        pub fn exit(code: Code) -> ! {
            unsafe {
                libc::exit(match code {
                    Code::Success => 0,
                    _ => 1,
                });
            }
        }

        pub fn xlate_fault(virt: VirtAddr, perm: kif::Perm) -> Result<(), Error> {
            crate::arch::linux::ioctl::tlb_insert_addr(virt, perm.bits() as u8);
            Ok(())
        }

        pub fn map(_virt: VirtAddr, _phys: PhysAddr, _pages: usize,
                   _access: kif::Perm) -> Result<(), Error> {
            Err(Error::new(Code::NotSup))
        }

        pub fn reg_irq(_irq: IRQId) -> Result<(), Error> {
            Err(Error::new(Code::NotSup))
        }

        pub fn flush_invalidate() -> Result<(), Error> {
            Err(Error::new(Code::NotSup))
        }

        #[inline(always)]
        pub fn switch_activity() -> Result<(), Error> {
            Err(Error::new(Code::NotSup))
        }

        #[inline(always)]
        pub fn noop() -> Result<(), Error> {
            Err(Error::new(Code::NotSup))
        }

        #[inline(always)]
        pub fn act_info() -> Result<(), Error> {
            Err(Error::new(Code::NotSup))
        }
    }
    else {
        use crate::arch::{TMABIOps, TMABI};
        use crate::tcu::INVALID_EP;

        #[inline(always)]
        pub fn wait(
            ep: Option<EpId>,
            irq: Option<IRQId>,
            duration: Option<TimeDuration>,
        ) -> Result<(), Error> {
            TMABI::call3(
                Operation::Wait,
                ep.unwrap_or(INVALID_EP) as usize,
                irq.unwrap_or(INVALID_IRQ) as usize,
                match duration {
                    Some(d) => d.as_nanos() as usize,
                    None => usize::MAX,
                },
            )
            .map(|_| ())
        }

        pub fn exit(code: Code) -> ! {
            TMABI::call1(Operation::Exit, code as usize).ok();
            unreachable!();
        }

        pub fn xlate_fault(virt: VirtAddr, perm: kif::Perm) -> Result<(), Error> {
            TMABI::call2(Operation::TranslFault, virt.as_local(), perm.bits() as usize)
        }

        pub fn map(virt: VirtAddr, phys: PhysAddr, pages: usize, access: kif::Perm) -> Result<(), Error> {
            TMABI::call4(
                Operation::Map,
                virt.as_local(),
                phys.as_raw() as usize,
                pages,
                access.bits() as usize,
            )
        }

        pub fn reg_irq(irq: IRQId) -> Result<(), Error> {
            TMABI::call1(Operation::RegIRQ, irq as usize)
        }

        pub fn flush_invalidate() -> Result<(), Error> {
            TMABI::call1(Operation::FlushInv, 0)
        }

        #[inline(always)]
        pub fn switch_activity() -> Result<(), Error> {
            TMABI::call1(Operation::Yield, 0)
        }

        #[inline(always)]
        pub fn noop() -> Result<(), Error> {
            TMABI::call1(Operation::Noop, 0)
        }

        #[inline(always)]
        pub fn act_info(res: VirtAddr, addr: VirtAddr) -> Result<(), Error> {
            TMABI::call2(Operation::ActInfo, res.as_local(), addr.as_local())
        }
    }
}
