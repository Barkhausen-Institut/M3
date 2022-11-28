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

#![no_std]

mod loader;

use m3::boxed::Box;
use m3::cap::Selector;
use m3::cell::{LazyReadOnlyCell, StaticCell};
use m3::cfg;
use m3::col::ToString;
use m3::com::{MemGate, RGateArgs, RecvGate, SGateArgs, SendGate};
use m3::errors::{Code, Error, VerboseError};
use m3::goff;
use m3::kif;
use m3::log;
use m3::session::ResMng;
use m3::syscalls;
use m3::tcu;
use m3::tiles::{Activity, ActivityArgs, ChildActivity};
use m3::util::math;
use m3::vfs::{FileRef, Hashed};

use resmng::childs::{self, Child, OwnChild};
use resmng::{memory, requests, sendqueue, subsys};

static SUBSYS: LazyReadOnlyCell<subsys::Subsystem> = LazyReadOnlyCell::default();
static BMODS: StaticCell<u64> = StaticCell::new(0);

fn find_mod(name: &str) -> Option<(MemGate, usize)> {
    SUBSYS
        .get()
        .mods()
        .iter()
        .enumerate()
        .position(|(idx, m)| (BMODS.get() & (1 << idx)) == 0 && m.name() == name)
        .map(|idx| {
            BMODS.set(BMODS.get() | 1 << idx);
            (
                SUBSYS.get().get_mod(idx),
                SUBSYS.get().mods()[idx].size as usize,
            )
        })
}

fn start_child_async(child: &mut OwnChild) -> Result<(), VerboseError> {
    let bmod = find_mod(child.cfg().name()).ok_or_else(|| Error::new(Code::NotFound))?;

    #[allow(clippy::useless_conversion)]
    let sgate = SendGate::new_with(
        SGateArgs::new(&requests::rgate())
            .credits(1)
            .label(tcu::Label::from(child.id())),
    )?;

    let mut act = ChildActivity::new_with(
        child.child_tile().unwrap().tile_obj().clone(),
        ActivityArgs::new(child.name())
            .resmng(ResMng::new(sgate))
            .kmem(child.kmem().unwrap()),
    )
    .map_err(|e| VerboseError::new(e.code(), "Unable to create Activity".to_string()))?;

    if Activity::own().mounts().get_by_path("/").is_some() {
        act.add_mount("/", "/");
    }

    let id = child.id();
    if let Some(sub) = child.subsys() {
        sub.finalize_async(id, &mut act)
            .expect("Unable to finalize subsystem");
    }

    let mut bmapper = loader::BootMapper::new(
        act.sel(),
        bmod.0.sel(),
        act.tile_desc().has_virtmem(),
        child.mem().pool().clone(),
    );
    let bfile = loader::BootFile::new(bmod.0, bmod.1);

    // verify hash (current not support in root, but could be added to BootFile)
    if let Some(hash) = child.cfg().hash() {
        let filehash = bfile.hash().map_err(|e| {
            VerboseError::new(e.code(), "Unable to obtain application hash".to_string())
        })?;
        if filehash != *hash {
            panic!("{} has unexpected hash; stopping", child.name());
        }
    }

    let fd = Activity::own().files().add(Box::new(bfile))?;
    child
        .start(act, &mut bmapper, FileRef::new_owned(fd))
        .map_err(|e| VerboseError::new(e.code(), "Unable to start Activity".to_string()))?;

    for a in bmapper.fetch_allocs() {
        child.add_mem(a, None);
    }

    Ok(())
}

fn create_rgate(
    buf_size: usize,
    msg_size: usize,
    rbuf_mem: Option<Selector>,
    rbuf_off: goff,
    rbuf_addr: usize,
) -> Result<RecvGate, Error> {
    let rgate = RecvGate::new_with(
        RGateArgs::default()
            .order(math::next_log2(buf_size))
            .msg_order(math::next_log2(msg_size)),
    )?;
    rgate.activate_with(rbuf_mem, rbuf_off, rbuf_addr)?;
    Ok(rgate)
}

fn workloop() {
    requests::workloop(|| {}, start_child_async).expect("Running the workloop failed");
}

#[no_mangle]
pub fn main() -> Result<(), Error> {
    let sub = subsys::Subsystem::new().expect("Unable to read subsystem info");
    let args = sub.parse_args();
    SUBSYS.set(sub);

    let max_msg_size = 1 << 8;
    let buf_size = max_msg_size * args.max_clients;

    // allocate and map memory for receive buffer. note that we need to do that manually here,
    // because RecvBufs allocate new physical memory via the resource manager and root does not have
    // a resource manager.
    let (rbuf_addr, _) = Activity::own().tile_desc().rbuf_space();
    let (rbuf_off, rbuf_mem) = if Activity::own().tile_desc().has_virtmem() {
        let buf_mem = memory::container()
            .alloc_mem((buf_size + sendqueue::RBUF_SIZE) as goff)
            .expect("Unable to allocate memory for receive buffers");
        let pages = (buf_mem.capacity() as usize + cfg::PAGE_SIZE - 1) / cfg::PAGE_SIZE;
        syscalls::create_map(
            (rbuf_addr / cfg::PAGE_SIZE) as Selector,
            Activity::own().sel(),
            buf_mem.sel(),
            0,
            pages as Selector,
            kif::Perm::R,
        )
        .expect("Unable to map receive buffers");
        (0, Some(buf_mem.sel()))
    }
    else {
        (rbuf_addr as goff, None)
    };

    let req_rgate = create_rgate(buf_size, max_msg_size, rbuf_mem, rbuf_off, rbuf_addr)
        .expect("Unable to create request RecvGate");
    requests::init(req_rgate);

    let squeue_rgate = create_rgate(
        sendqueue::RBUF_SIZE,
        sendqueue::RBUF_MSG_SIZE,
        rbuf_mem,
        rbuf_off + buf_size as goff,
        rbuf_addr + buf_size,
    )
    .expect("Unable to create sendqueue RecvGate");
    sendqueue::init(squeue_rgate);

    thread::init();
    for _ in 0..args.max_clients {
        thread::add_thread(workloop as *const () as usize, 0);
    }

    SUBSYS
        .get()
        .start(start_child_async)
        .expect("Unable to start subsystem");

    childs::borrow_mut().start_waiting(1);

    workloop();

    log!(resmng::LOG_DEF, "All childs gone. Exiting.");

    Ok(())
}
