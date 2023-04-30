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

mod addrspace;
mod dataspace;
mod mapper;
mod physmem;
mod regions;

use core::convert::TryFrom;
use core::ops::DerefMut;

use m3::boxed::Box;
use m3::cell::LazyStaticRefCell;
use m3::col::{String, ToString, Vec};
use m3::com::{opcodes, MemGate, RecvGate, SGateArgs, SendGate};
use m3::errors::{Code, Error, VerboseError};
use m3::format;
use m3::server::{ExcType, RequestHandler, Server};
use m3::session::{ClientSession, Pager, ResMng, M3FS};
use m3::tcu::Label;
use m3::tiles::{Activity, ActivityArgs, ChildActivity};
use m3::util::math;
use m3::vfs;

use addrspace::AddrSpace;

use resmng::childs::{self, Child, ChildManager, OwnChild};
use resmng::config;
use resmng::requests;
use resmng::resources::{tiles, Resources};
use resmng::sendqueue;
use resmng::subsys;

static REQHDL: LazyStaticRefCell<RequestHandler<AddrSpace, opcodes::Pager>> =
    LazyStaticRefCell::default();

static MOUNTS: LazyStaticRefCell<Vec<(String, String)>> = LazyStaticRefCell::default();

fn get_mount(name: &str) -> Result<String, VerboseError> {
    for (n, mpath) in MOUNTS.borrow().iter() {
        if n == name {
            return Ok(mpath.clone());
        }
    }

    let id = MOUNTS.borrow().len();
    let fs = M3FS::new(id, name).map_err(|e| {
        VerboseError::new(e.code(), format!("Unable to open m3fs session {}", name))
    })?;
    let our_path = format!("/child-mount-{}", name);
    Activity::own().mounts().add(&our_path, fs)?;
    MOUNTS
        .borrow_mut()
        .push((name.to_string(), our_path.to_string()));
    Ok(our_path)
}

struct PagedChildStarter {}

impl subsys::ChildStarter for PagedChildStarter {
    fn start(
        &mut self,
        reqs: &requests::Requests,
        res: &mut Resources,
        child: &mut OwnChild,
    ) -> Result<(), VerboseError> {
        // send gate for resmng
        let resmng_sgate = SendGate::new_with(
            SGateArgs::new(reqs.recv_gate())
                .credits(1)
                .label(Label::from(child.id())),
        )?;

        // create pager session for child (creator=0 here because we create all sessions ourself)
        let (child_sess, child_sgate, pager_sgate, child_sid) = {
            let mut hdl = REQHDL.borrow_mut();
            let cli = hdl.clients_mut();
            let (sel, nsid) = cli.add_connected_session(0, |_hdl, serv, _sgate| {
                Ok(AddrSpace::new(serv, None, None))
            })?;
            let pf_sgate = cli.add_connection(nsid)?;
            (ClientSession::new_bind(sel + 0), sel + 1, pf_sgate, nsid)
        };

        // create child activity
        let mut act = ChildActivity::new_with(
            child.child_tile().unwrap().tile_obj().clone(),
            ActivityArgs::new(child.name())
                .resmng(ResMng::new(resmng_sgate))
                .pager(Pager::new(child_sess, pager_sgate, child_sgate)?)
                .kmem(child.kmem().unwrap()),
        )?;

        // pass subsystem info to child, if it's a subsystem
        let id = child.id();
        if let Some(sub) = child.subsys() {
            sub.finalize_async(res, id, &mut act)?;
        }

        // mount file systems for childs
        for m in child.cfg().mounts() {
            let path = get_mount(m.fs())?;
            act.add_mount(m.path(), &path);
        }

        // init address space (give it activity and mgate selector)
        let mut hdl = REQHDL.borrow_mut();
        let aspace = hdl.clients_mut().sessions_mut().get_mut(child_sid).unwrap();
        aspace.do_init(Some(child.id()), Some(act.sel())).unwrap();

        // start activity
        let file = vfs::VFS::open(child.name(), vfs::OpenFlags::RX | vfs::OpenFlags::NEW_SESS)
            .map_err(|e| VerboseError::new(e.code(), format!("Unable to open {}", child.name())))?;
        let mut mapper = mapper::ChildMapper::new(aspace, act.tile_desc().has_virtmem());

        let run = act
            .exec_file(&mut mapper, file.into_generic(), child.arguments())
            .map_err(|e| {
                VerboseError::new(e.code(), format!("Unable to execute {}", child.name()))
            })?;

        child.set_running(Box::new(run));

        Ok(())
    }

    fn configure_tile(
        &mut self,
        _res: &mut Resources,
        tile: &tiles::TileUsage,
        _domain: &config::Domain,
    ) -> Result<(), VerboseError> {
        let fs_mod = MemGate::new_bind_bootmod("fs")?;
        let fs_mod_size = fs_mod.region()?.1 as usize;
        // don't overwrite PMP EPs here, but use the next free one. this is required in case we
        // share our tile with this child and therefore need to add a PMP EP for ourself. Since our
        // parent has already set PMP EPs, we don't want to overwrite them.
        tile.add_mem_region(fs_mod, fs_mod_size, true, false)
            .map_err(|e| {
                VerboseError::new(e.code(), "Unable to add PMP EP for FS image".to_string())
            })
    }
}

#[allow(clippy::vec_box)]
struct WorkloopArgs<'c, 'd, 'r, 'q, 's> {
    childs: &'c mut ChildManager,
    delayed: &'d mut Vec<Box<OwnChild>>,
    res: &'r mut Resources,
    reqs: &'q requests::Requests,
    serv: &'s mut Server,
}

fn workloop(args: &mut WorkloopArgs<'_, '_, '_, '_, '_>) {
    let WorkloopArgs {
        childs,
        delayed,
        res,
        reqs,
        serv,
    } = args;

    reqs.run_loop(
        childs,
        delayed,
        res,
        |mut childs, _res| {
            serv.fetch_and_handle(REQHDL.borrow_mut().deref_mut()).ok();

            REQHDL
                .borrow_mut()
                .fetch_and_handle_with(|_handler, opcode, sess, is| match opcodes::Pager::try_from(
                    opcode,
                ) {
                    Ok(opcodes::Pager::Pagefault) => sess.pagefault(&mut childs, is),
                    Ok(opcodes::Pager::MapAnon) => sess.map_anon(is),
                    Ok(opcodes::Pager::Unmap) => sess.unmap(is),
                    Ok(opcodes::Pager::Close) => sess.close(is),
                    _ => Err(Error::new(Code::InvArgs)),
                })
                .ok();
        },
        &mut PagedChildStarter {},
    )
    .expect("Unable to run workloop");
}

#[no_mangle]
pub fn main() -> Result<(), Error> {
    let (subsys, mut res) = subsys::Subsystem::new().expect("Unable to read subsystem info");

    let args = subsys.parse_args();
    for sem in &args.sems {
        res.semaphores_mut()
            .add_sem(sem.clone())
            .expect("Unable to add semaphore");
    }

    // mount root FS if we haven't done that yet
    MOUNTS.set(Vec::new());
    if vfs::VFS::stat("/").is_err() {
        vfs::VFS::mount("/", "m3fs", "m3fs").expect("Unable to mount root filesystem");
    }
    MOUNTS
        .borrow_mut()
        .push(("m3fs".to_string(), "/".to_string()));

    // create request handler and server
    let mut hdl = RequestHandler::new_with(args.max_clients, 128, 3)
        .expect("Unable to create request handler");
    let mut srv = Server::new_private("pager", &mut hdl).expect("Unable to create service");

    use opcodes::Pager;
    hdl.reg_cap_handler(Pager::Init, ExcType::Del(1), AddrSpace::init);
    hdl.reg_cap_handler(Pager::AddChild, ExcType::Obt(1), AddrSpace::add_child);
    hdl.reg_cap_handler(Pager::MapDS, ExcType::Del(1), AddrSpace::map_ds);
    hdl.reg_cap_handler(Pager::MapMem, ExcType::Del(1), AddrSpace::map_mem);
    REQHDL.set(hdl);

    let req_rgate = RecvGate::new(
        math::next_log2(256 * args.max_clients),
        math::next_log2(256),
    )
    .expect("Unable to create resmng RecvGate");
    // manually activate the RecvGate here, because it requires quite a lot of EPs and we are
    // potentially moving (<EPs left> - 16) EPs to a child activity. therefore, we should allocate
    // all EPs before starting childs.
    req_rgate
        .activate()
        .expect("Unable to activate resmng RecvGate");
    let reqs = requests::Requests::new(req_rgate);

    let squeue_rgate = RecvGate::new(
        math::next_log2(sendqueue::RBUF_MSG_SIZE * args.max_clients),
        math::next_log2(sendqueue::RBUF_MSG_SIZE),
    )
    .expect("Unable to create sendqueue RecvGate");
    squeue_rgate
        .activate()
        .expect("Unable to activate sendqueue RecvGate");
    sendqueue::init(squeue_rgate);

    let mut childs = childs::ChildManager::default();

    let mut delayed = subsys
        .start(&mut childs, &reqs, &mut res, &mut PagedChildStarter {})
        .expect("Unable to start subsystem");

    let mut wargs = WorkloopArgs {
        childs: &mut childs,
        delayed: &mut delayed,
        res: &mut res,
        reqs: &reqs,
        serv: &mut srv,
    };

    thread::init();
    for _ in 0..args.max_clients {
        thread::add_thread(
            workloop as *const () as usize,
            &mut wargs as *mut _ as usize,
        );
    }

    wargs.childs.start_waiting(1);

    workloop(&mut wargs);

    Ok(())
}
