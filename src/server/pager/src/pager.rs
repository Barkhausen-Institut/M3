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

use core::ops::DerefMut;

use m3::cap::Selector;
use m3::cell::{LazyReadOnlyCell, LazyStaticRefCell, StaticRefCell};
use m3::col::{String, ToString, Vec};
use m3::com::{GateIStream, MGateArgs, MemGate, RecvGate, SGateArgs, SendGate};
use m3::env;
use m3::errors::{Code, Error, VerboseError};
use m3::format;
use m3::kif;
use m3::log;
use m3::math;
use m3::println;
use m3::server::{
    CapExchange, Handler, RequestHandler, Server, SessId, SessionContainer, DEF_MSG_SIZE,
};
use m3::session::{ClientSession, Pager, PagerOp, ResMng, M3FS};
use m3::tcu::{Label, TileId};
use m3::tiles::{Activity, ActivityArgs, ChildActivity};
use m3::vfs;

use addrspace::AddrSpace;
use resmng::childs::{self, Child, OwnChild};
use resmng::{requests, sendqueue, subsys};

pub const LOG_DEF: bool = false;

static PGHDL: LazyStaticRefCell<PagerReqHandler> = LazyStaticRefCell::default();
static REQHDL: LazyReadOnlyCell<RequestHandler> = LazyReadOnlyCell::default();
static MOUNTS: LazyStaticRefCell<Vec<(String, String)>> = LazyStaticRefCell::default();
static PMP_TILES: StaticRefCell<Vec<TileId>> = StaticRefCell::new(Vec::new());
static SETTINGS: LazyStaticRefCell<PagerSettings> = LazyStaticRefCell::default();

struct PagerReqHandler {
    sel: Selector,
    sessions: SessionContainer<AddrSpace>,
}

impl PagerReqHandler {
    fn close_sess(&mut self, _crt: usize, sid: SessId, rgate: &RecvGate) {
        log!(crate::LOG_DEF, "[{}] pager::close()", sid);
        let crt = self.sessions.get(sid).unwrap().creator();
        self.sessions.remove(crt, sid);
        // ignore all potentially outstanding messages of this session
        rgate.drop_msgs_with(sid as Label);
    }
}

impl Handler<AddrSpace> for PagerReqHandler {
    fn sessions(&mut self) -> &mut m3::server::SessionContainer<AddrSpace> {
        &mut self.sessions
    }

    fn open(
        &mut self,
        crt: usize,
        srv_sel: Selector,
        _arg: &str,
    ) -> Result<(Selector, SessId), Error> {
        self.sessions.add_next(crt, srv_sel, false, |sess| {
            log!(crate::LOG_DEF, "[{}] pager::open()", sess.ident());
            Ok(AddrSpace::new(crt, sess, None, None))
        })
    }

    fn obtain(&mut self, crt: usize, sid: SessId, xchg: &mut CapExchange<'_>) -> Result<(), Error> {
        if xchg.in_caps() != 1 {
            return Err(Error::new(Code::InvArgs));
        }

        let aspace = self.sessions.get_mut(sid).unwrap();

        let op = xchg.in_args().pop_word()? as u32;
        let sel = match PagerOp::from(op) {
            PagerOp::ADD_CHILD => {
                let sid = aspace.id();
                let child_id = aspace.child_id();
                self.sessions
                    .add_next(crt, self.sel, false, |sess| {
                        let nsid = sess.ident();
                        log!(crate::LOG_DEF, "[{}] pager::add_child(nsid={})", sid, nsid);
                        Ok(AddrSpace::new(crt, sess, Some(sid), child_id))
                    })
                    .map(|(sel, _)| sel)
            },
            PagerOp::ADD_SGATE => aspace.add_sgate(REQHDL.get().recv_gate()),
            _ => Err(Error::new(Code::InvArgs)),
        }?;

        xchg.out_caps(kif::CapRngDesc::new(kif::CapType::OBJECT, sel, 1));
        Ok(())
    }

    fn delegate(
        &mut self,
        _crt: usize,
        sid: SessId,
        xchg: &mut CapExchange<'_>,
    ) -> Result<(), Error> {
        if xchg.in_caps() != 1 {
            return Err(Error::new(Code::InvArgs));
        }

        let aspace = self.sessions.get_mut(sid).unwrap();

        let args = xchg.in_args();
        let op = args.pop_word()? as u32;
        let (sel, virt) = match PagerOp::from(op) {
            PagerOp::INIT => aspace.init(None, None).map(|sel| (sel, 0)),
            PagerOp::MAP_DS => aspace.map_ds(args),
            PagerOp::MAP_MEM => aspace.map_mem(args),
            _ => Err(Error::new(Code::InvArgs)),
        }?;

        if virt != 0 {
            xchg.out_args().push_word(virt);
        }

        xchg.out_caps(kif::CapRngDesc::new(kif::CapType::OBJECT, sel, 1));
        Ok(())
    }

    fn close(&mut self, _crt: usize, sid: SessId) {
        self.close_sess(_crt, sid, REQHDL.get().recv_gate());
    }
}

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

fn start_child_async(child: &mut OwnChild) -> Result<(), VerboseError> {
    // send gate for resmng
    #[allow(clippy::useless_conversion)]
    let resmng_sgate = SendGate::new_with(
        SGateArgs::new(&requests::rgate())
            .credits(1)
            .label(Label::from(child.id())),
    )?;

    // create pager session for child (creator=0 here because we create all sessions ourself)
    let (sel, sid, child_sgate) = {
        let mut hdl = PGHDL.borrow_mut();
        let srv_sel = hdl.sel;
        let (sel, sid) = hdl.open(0, srv_sel, "")?;
        let aspace = hdl.sessions.get_mut(sid).unwrap();
        let child_sgate = aspace.add_sgate(REQHDL.get().recv_gate()).unwrap();
        (sel, sid, child_sgate)
    };
    let sess = ClientSession::new_bind(sel);
    #[allow(clippy::useless_conversion)]
    let pager_sgate = SendGate::new_with(
        SGateArgs::new(REQHDL.get().recv_gate())
            .credits(1)
            .label(Label::from(sid as u32)),
    )?;

    // create child activity
    let tile_usage = child.child_tile().unwrap();
    let mut act = ChildActivity::new_with(
        tile_usage.tile_obj().clone(),
        ActivityArgs::new(child.name())
            .resmng(ResMng::new(resmng_sgate))
            .pager(Pager::new(sess, pager_sgate, child_sgate)?)
            .kmem(child.kmem().unwrap()),
    )?;

    // TODO make that more flexible
    // add PMP EP for file system
    {
        let mut pmp_tiles = PMP_TILES.borrow_mut();
        if !pmp_tiles.iter().any(|id| *id == tile_usage.tile_id()) {
            let size = SETTINGS.borrow().fs_size;
            let fs_mem = MemGate::new_with(MGateArgs::new(size, kif::Perm::R).addr(0))?;
            child.our_tile().add_mem_region(fs_mem, size, true)?;
            pmp_tiles.push(tile_usage.tile_id());
        }
    }

    // pass subsystem info to child, if it's a subsystem
    let id = child.id();
    if let Some(sub) = child.subsys() {
        sub.finalize_async(id, &mut act)?;
    }

    // mount file systems for childs
    for m in child.cfg().mounts() {
        let path = get_mount(m.fs())?;
        act.add_mount(m.path(), &path);
    }

    // init address space (give it activity and mgate selector)
    let mut hdl = PGHDL.borrow_mut();
    let aspace = hdl.sessions.get_mut(sid).unwrap();
    aspace.init(Some(child.id()), Some(act.sel())).unwrap();

    // start activity
    let file = vfs::VFS::open(child.name(), vfs::OpenFlags::RX | vfs::OpenFlags::NEW_SESS)
        .map_err(|e| VerboseError::new(e.code(), format!("Unable to open {}", child.name())))?;
    let mut mapper = mapper::ChildMapper::new(aspace, act.tile_desc().has_virtmem());
    child
        .start(act, Some((&mut mapper, file.into_generic())))
        .map_err(|e| VerboseError::new(e.code(), "Unable to start Activity".to_string()))
}

fn handle_request(op: PagerOp, is: &mut GateIStream<'_>) -> Result<(), Error> {
    let mut hdl = PGHDL.borrow_mut();
    let sid = is.label() as SessId;

    // clone is special, because we need two sessions
    if op == PagerOp::CLONE {
        let pid = hdl.sessions.get(sid).unwrap().parent();
        if let Some(pid) = pid {
            let (sess, psess) = hdl.sessions.get_two_mut(sid, pid);
            let sess = sess.unwrap();
            sess.clone(is, psess.unwrap())
        }
        else {
            Err(Error::new(Code::InvArgs))
        }
    }
    else {
        let aspace = hdl.sessions.get_mut(sid).unwrap();

        match op {
            PagerOp::PAGEFAULT => aspace.pagefault(is),
            PagerOp::MAP_ANON => aspace.map_anon(is),
            PagerOp::UNMAP => aspace.unmap(is),
            PagerOp::CLOSE => aspace
                .close(is)
                .map(|_| hdl.close_sess(0, is.label() as SessId, is.rgate())),
            _ => Err(Error::new(Code::InvArgs)),
        }
    }
}

fn workloop(serv: &Server) {
    requests::workloop(
        || {
            serv.handle_ctrl_chan(PGHDL.borrow_mut().deref_mut()).ok();

            REQHDL.get().handle(handle_request).ok();
        },
        start_child_async,
    )
    .expect("Unable to run workloop");
}

#[derive(Clone, Debug)]
pub struct PagerSettings {
    fs_size: usize,
}

fn parse_args() -> Result<PagerSettings, String> {
    Ok(PagerSettings {
        fs_size: env::args()
            .last()
            .ok_or("File system size missing")?
            .parse::<usize>()
            .map_err(|_| String::from("Failed to parse FS size"))?,
    })
}

#[no_mangle]
pub fn main() -> i32 {
    SETTINGS.set(parse_args().unwrap_or_else(|e| {
        println!("Invalid arguments: {}", e);
        m3::exit(1);
    }));

    let subsys = subsys::Subsystem::new().expect("Unable to read subsystem info");

    let args = subsys.parse_args();

    // mount root FS if we haven't done that yet
    MOUNTS.set(Vec::new());
    if vfs::VFS::stat("/").is_err() {
        vfs::VFS::mount("/", "m3fs", "m3fs").expect("Unable to mount root filesystem");
    }
    MOUNTS
        .borrow_mut()
        .push(("m3fs".to_string(), "/".to_string()));

    // create server
    let mut hdl = PagerReqHandler {
        sel: 0,
        sessions: SessionContainer::new(args.max_clients),
    };
    let serv = Server::new_private("pager", &mut hdl).expect("Unable to create service");
    hdl.sel = serv.sel();
    PGHDL.set(hdl);

    REQHDL.set(
        RequestHandler::new_with(args.max_clients, DEF_MSG_SIZE)
            .expect("Unable to create request handler"),
    );

    let mut req_rgate = RecvGate::new(
        math::next_log2(256 * args.max_clients),
        math::next_log2(256),
    )
    .expect("Unable to create resmng RecvGate");
    req_rgate
        .activate()
        .expect("Unable to activate resmng RecvGate");
    requests::init(req_rgate);

    let mut squeue_rgate = RecvGate::new(
        math::next_log2(sendqueue::RBUF_MSG_SIZE * args.max_clients),
        math::next_log2(sendqueue::RBUF_MSG_SIZE),
    )
    .expect("Unable to create sendqueue RecvGate");
    squeue_rgate
        .activate()
        .expect("Unable to activate sendqueue RecvGate");
    sendqueue::init(squeue_rgate);

    thread::init();
    for _ in 0..args.max_clients {
        thread::add_thread(workloop as *const () as usize, &serv as *const _ as usize);
    }

    subsys
        .start(start_child_async)
        .expect("Unable to start subsystem");

    childs::borrow_mut().start_waiting(1);

    workloop(&serv);

    0
}
