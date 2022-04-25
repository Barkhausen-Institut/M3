/*
 * Copyright (C) 2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
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

use base;
use base::format;

use crate::arch;
use crate::cap::Selector;
use crate::cell::LazyReadOnlyCell;
use crate::col::{String, Vec};
use crate::com::SendGate;
use crate::kif::{self, TileDesc, TileISA, TileType};
use crate::libc;
use crate::serialize::Source;
use crate::session::{Pager, ResMng};
use crate::tcu::{ActId, EpId, Label};
use crate::vfs::{FileTable, MountTable};

pub struct EnvData {
    sysc_crd: u64,
    sysc_lbl: Label,
    sysc_ep: EpId,
    _shm_prefix: String,
}

impl EnvData {
    fn base(&self) -> &base::envdata::EnvData {
        base::envdata::get()
    }

    pub fn activity_id(&self) -> ActId {
        self.sysc_lbl as ActId
    }

    pub fn tile_id(&self) -> u64 {
        self.base().tile_id
    }

    pub fn shared(&self) -> bool {
        self.base().shared != 0
    }

    pub fn tile_desc(&self) -> TileDesc {
        TileDesc::new_from(self.base().tile_desc)
    }

    pub fn first_std_ep(&self) -> EpId {
        0
    }

    pub fn load_pager(&self) -> Option<Pager> {
        None
    }

    pub fn load_rmng(&self) -> Option<ResMng> {
        match Self::load_word("rmng", 0) as Selector {
            0 => None,
            s => Some(ResMng::new(SendGate::new_bind(s))),
        }
    }

    pub fn load_first_sel(&self) -> Selector {
        if self.base().first_sel != 0 {
            self.base().first_sel as Selector
        }
        else {
            Self::load_word("nextsel", kif::FIRST_FREE_SEL) as Selector
        }
    }

    pub fn load_mounts(&self) -> MountTable {
        match arch::loader::read_env_words("ms") {
            Some(ms) => MountTable::unserialize(&mut Source::new(&ms)),
            None => MountTable::default(),
        }
    }

    pub fn load_fds(&self) -> FileTable {
        match arch::loader::read_env_words("fds") {
            Some(fds) => FileTable::unserialize(&mut Source::new(&fds)),
            None => FileTable::default(),
        }
    }

    pub fn load_data(&self) -> Vec<u64> {
        match arch::loader::read_env_words("data") {
            Some(data) => data,
            None => Vec::default(),
        }
    }

    pub fn load_func(&self) -> Option<fn() -> i32> {
        // safety: we trust our loader
        arch::loader::read_env_words("lambda")
            .map(|addr| unsafe { core::intrinsics::transmute(addr[0]) })
    }

    fn load_word(name: &str, default: u64) -> u64 {
        match arch::loader::read_env_words(name) {
            Some(buf) => Source::new(&buf).pop().unwrap(),
            None => default,
        }
    }

    // --- host specific API ---

    pub fn syscall_params(&self) -> (EpId, Label, u64) {
        (self.sysc_ep, self.sysc_lbl, self.sysc_crd)
    }
}

fn read_line(fd: i32) -> String {
    let mut vec = Vec::new();
    loop {
        let mut buf = [0u8; 1];
        if unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 1) } == 0 {
            break;
        }
        if buf[0] == b'\n' {
            break;
        }
        vec.push(buf[0]);
    }
    unsafe { String::from_utf8_unchecked(vec) }
}

static ENV_DATA: LazyReadOnlyCell<EnvData> = LazyReadOnlyCell::default();

pub fn get() -> &'static EnvData {
    ENV_DATA.get()
}

pub fn init(argc: i32, argv: *const *const i8) {
    let fd = unsafe {
        let path = format!("{}/{}\0", base::envdata::tmp_dir(), libc::getpid());
        libc::open(path.as_ptr() as *const libc::c_char, libc::O_RDONLY)
    };
    assert!(fd != -1);

    let shm_prefix = read_line(fd);

    let base = base::envdata::EnvData::new(
        read_line(fd).parse::<u64>().unwrap(),
        TileDesc::new(TileType::COMP_IMEM, TileISA::X86, 1024 * 1024),
        argc,
        argv,
        read_line(fd).parse::<Selector>().unwrap(),
        read_line(fd).parse::<Selector>().unwrap(),
    );
    base::envdata::set(base);

    ENV_DATA.set(EnvData {
        sysc_lbl: read_line(fd).parse::<Label>().unwrap(),
        sysc_ep: read_line(fd).parse::<EpId>().unwrap(),
        sysc_crd: read_line(fd).parse::<u64>().unwrap(),
        _shm_prefix: shm_prefix,
    });

    unsafe {
        libc::close(fd);
    }

    // load the env vars that our parent passed to us
    if let Some(vars) = arch::loader::read_env_words("vars") {
        let mut src = Source::new(&vars);
        while let Ok(var) = src.pop_str() {
            let mut parts = var.split('=');
            crate::env::set_var(parts.next().unwrap(), parts.next().unwrap());
        }
    }
}
