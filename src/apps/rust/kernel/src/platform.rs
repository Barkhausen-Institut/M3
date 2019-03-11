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

use arch;
use base::cell::StaticCell;
use base::dtu::PEId;
use base::goff;
use base::kif::PEDesc;
use core::iter;

pub const MAX_MODS: usize   = 64;
pub const MAX_PES: usize    = 64;

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct KEnv {
    pub mods: [u64; MAX_MODS],
    pub pe_count: u64,
    pub pes: [u32; MAX_PES],
}

pub struct PEIterator {
    id: PEId,
    last: PEId,
}

impl iter::Iterator for PEIterator {
    type Item = PEId;

    fn next(&mut self) -> Option<Self::Item> {
        if self.id <= self.last {
            self.id += 1;
            Some(self.id - 1)
        }
        else {
            None
        }
    }
}

static KENV: StaticCell<Option<KEnv>> = StaticCell::new(None);

pub fn init() {
    KENV.set(Some(arch::platform::init()));
}

fn get() -> &'static mut KEnv {
    KENV.get_mut().as_mut().unwrap()
}

#[cfg(target_os = "none")]
pub struct ModIterator {
    idx: usize,
}

#[cfg(target_os = "none")]
impl iter::Iterator for ModIterator {
    type Item = base::mem::GlobAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.idx += 1;
        match {get().mods}[self.idx - 1] {
            0 => None,
            a => Some(base::mem::GlobAddr::new(a)),
        }
    }
}

pub fn pe_count() -> usize {
    get().pe_count as usize
}
pub fn pes() -> PEIterator {
    PEIterator {
        id: 0,
        last: pe_count() - 1,
    }
}
pub fn kernel_pe() -> PEId {
    arch::platform::kernel_pe()
}
pub fn user_pes() -> PEIterator {
    PEIterator {
        id: arch::platform::first_user_pe(),
        last: arch::platform::last_user_pe(),
    }
}

pub fn pe_desc(pe: PEId) -> PEDesc {
    PEDesc::new_from(get().pes[pe])
}

pub fn default_rcvbuf(pe: PEId) -> goff {
    arch::platform::default_rcvbuf(pe)
}
pub fn rcvbufs_size(pe: PEId) -> usize {
    arch::platform::rcvbufs_size(pe)
}

#[cfg(target_os = "none")]
pub fn mods() -> ModIterator {
    ModIterator {
        idx: 0,
    }
}
