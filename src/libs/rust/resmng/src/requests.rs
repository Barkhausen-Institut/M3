/*
 * Copyright (C) 2020-2022 Nils Asmussen, Barkhausen Institut
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

use m3::cell::{LazyStaticRefCell, Ref};
use m3::col::String;
use m3::com::{GateIStream, RecvGate};
use m3::errors::{Code, Error, VerboseError};
use m3::log;
use m3::reply_vmsg;
use m3::session::{resmng, sig};
use m3::tiles::Activity;

use crate::childs::{self, Id};
use crate::sendqueue;
use crate::subsys;

static RGATE: LazyStaticRefCell<RecvGate> = LazyStaticRefCell::default();

pub fn init(rgate: RecvGate) {
    RGATE.set(rgate);
}

pub fn rgate() -> Ref<'static, RecvGate> {
    RGATE.borrow()
}

pub fn workloop<F, S>(mut func: F, mut spawn: S) -> Result<(), VerboseError>
where
    F: FnMut(),
    S: FnMut(&mut childs::OwnChild) -> Result<(), VerboseError>,
{
    let upcall_rg = RecvGate::upcall();

    loop {
        {
            let rgate = RGATE.borrow();
            if let Ok(msg) = rgate.fetch() {
                let is = GateIStream::new(msg, &rgate);
                handle_request_async(is);
                subsys::start_delayed_async(&mut spawn)?;
            }
        }

        if let Ok(msg) = upcall_rg.fetch() {
            childs::ChildManager::handle_upcall_async(msg);
        }

        sendqueue::check_replies();

        func();

        if thread::ready_count() > 0 {
            thread::try_yield();
        }

        if childs::borrow_mut().should_stop() {
            break;
        }

        Activity::own().sleep().ok();
    }

    if !thread::cur().is_main() {
        thread::stop();
        // just in case there is no ready thread
        Activity::own().exit(Ok(()));
    }
    Ok(())
}

fn handle_request_async(mut is: GateIStream<'_>) {
    let op: Result<resmng::Operation, Error> = is.pop();
    let id = is.label() as Id;

    let res = match op {
        Ok(resmng::Operation::REG_SERV) => reg_serv(&mut is, id),
        Ok(resmng::Operation::UNREG_SERV) => unreg_serv(&mut is, id),

        Ok(resmng::Operation::OPEN_SESS) => open_session_async(&mut is, id),
        Ok(resmng::Operation::CLOSE_SESS) => close_session_async(&mut is, id),

        Ok(resmng::Operation::ADD_CHILD) => add_child(&mut is, id),
        Ok(resmng::Operation::REM_CHILD) => rem_child_async(&mut is, id),

        Ok(resmng::Operation::ALLOC_MEM) => alloc_mem(&mut is, id),
        Ok(resmng::Operation::FREE_MEM) => free_mem(&mut is, id),

        Ok(resmng::Operation::ALLOC_TILE) => match alloc_tile(&mut is, id) {
            // reply already done
            Ok(_) => return,
            Err(e) => Err(e),
        },
        Ok(resmng::Operation::FREE_TILE) => free_tile(&mut is, id),

        Ok(resmng::Operation::USE_RGATE) => match use_rgate(&mut is, id) {
            // reply already done
            Ok(_) => return,
            Err(e) => Err(e),
        },
        Ok(resmng::Operation::USE_SGATE) => use_sgate(&mut is, id),

        Ok(resmng::Operation::USE_SEM) => use_sem(&mut is, id),

        Ok(resmng::Operation::GET_SERIAL) => get_serial(&mut is, id),

        Ok(resmng::Operation::GET_INFO) => get_info(&mut is, id),

        Ok(resmng::Operation::QUOTE) => quote(&mut is, id),

        _ => Err(Error::new(Code::InvArgs)),
    };

    match res {
        Err(e) => {
            let mut childs = childs::borrow_mut();
            let child = childs.child_by_id_mut(id).unwrap();
            log!(crate::LOG_DEF, "{}: {:?} failed: {}", child.name(), op, e);
            is.reply_error(e.code())
        },
        Ok(_) => is.reply_error(Code::Success),
    }
    .ok(); // ignore errors; we might have removed the child in the meantime
}

fn reg_serv(is: &mut GateIStream<'_>, id: Id) -> Result<(), Error> {
    let req: resmng::RegServiceReq = is.pop()?;

    let mut childs = childs::borrow_mut();
    let child = childs.child_by_id_mut(id).unwrap();
    child.reg_service(req.dst, req.sgate, req.name, req.sessions)
}

fn unreg_serv(is: &mut GateIStream<'_>, id: Id) -> Result<(), Error> {
    let req: resmng::FreeReq = is.pop()?;

    let mut childs = childs::borrow_mut();
    let child = childs.child_by_id_mut(id).unwrap();
    child.unreg_service(req.sel)
}

fn open_session_async(is: &mut GateIStream<'_>, id: Id) -> Result<(), Error> {
    let req: resmng::OpenSessionReq = is.pop()?;

    childs::open_session_async(id, req.dst, &req.name)
}

fn close_session_async(is: &mut GateIStream<'_>, id: Id) -> Result<(), Error> {
    let req: resmng::FreeReq = is.pop()?;

    childs::close_session_async(id, req.sel)
}

fn add_child(is: &mut GateIStream<'_>, id: Id) -> Result<(), Error> {
    let req: resmng::AddChildReq = is.pop()?;

    childs::add_child(id, req.id, req.sel, &RGATE.borrow(), req.sgate, req.name)
}

fn rem_child_async(is: &mut GateIStream<'_>, id: Id) -> Result<(), Error> {
    let req: resmng::FreeReq = is.pop()?;

    childs::rem_child_async(id, req.sel)
}

fn alloc_mem(is: &mut GateIStream<'_>, id: Id) -> Result<(), Error> {
    let req: resmng::AllocMemReq = is.pop()?;

    let mut childs = childs::borrow_mut();
    let child = childs.child_by_id_mut(id).unwrap();
    if req.addr == !0 {
        child.alloc_mem(req.dst, req.size, req.perms)
    }
    else {
        child.alloc_mem_at(req.dst, req.addr, req.size, req.perms)
    }
}

fn free_mem(is: &mut GateIStream<'_>, id: Id) -> Result<(), Error> {
    let req: resmng::FreeReq = is.pop()?;

    let mut childs = childs::borrow_mut();
    let child = childs.child_by_id_mut(id).unwrap();
    child.free_mem(req.sel)
}

fn alloc_tile(is: &mut GateIStream<'_>, id: Id) -> Result<(), Error> {
    let req: resmng::AllocTileReq = is.pop()?;

    let mut childs = childs::borrow_mut();
    let child = childs.child_by_id_mut(id).unwrap();
    child
        .alloc_tile(req.dst, req.desc)
        .and_then(|(id, desc)| reply_vmsg!(is, Code::Success, resmng::AllocTileReply { id, desc }))
}

fn free_tile(is: &mut GateIStream<'_>, id: Id) -> Result<(), Error> {
    let req: resmng::FreeReq = is.pop()?;

    let mut childs = childs::borrow_mut();
    let child = childs.child_by_id_mut(id).unwrap();
    child.free_tile(req.sel)
}

fn use_rgate(is: &mut GateIStream<'_>, id: Id) -> Result<(), Error> {
    let req: resmng::UseReq = is.pop()?;

    let mut childs = childs::borrow_mut();
    let child = childs.child_by_id_mut(id).unwrap();
    child
        .use_rgate(&req.name, req.dst)
        .and_then(|(order, msg_order)| {
            reply_vmsg!(is, Code::Success, resmng::UseRGateReply {
                order,
                msg_order
            })
        })
}

fn use_sgate(is: &mut GateIStream<'_>, id: Id) -> Result<(), Error> {
    let req: resmng::UseReq = is.pop()?;

    let mut childs = childs::borrow_mut();
    let child = childs.child_by_id_mut(id).unwrap();
    child.use_sgate(&req.name, req.dst)
}

fn use_sem(is: &mut GateIStream<'_>, id: Id) -> Result<(), Error> {
    let req: resmng::UseReq = is.pop()?;

    let mut childs = childs::borrow_mut();
    let child = childs.child_by_id_mut(id).unwrap();
    child.use_sem(&req.name, req.dst)
}

fn get_serial(is: &mut GateIStream<'_>, id: Id) -> Result<(), Error> {
    let req: resmng::GetSerialReq = is.pop()?;

    let mut childs = childs::borrow_mut();
    let child = childs.child_by_id_mut(id).unwrap();
    child.get_serial(req.dst)
}

fn get_info(is: &mut GateIStream<'_>, id: Id) -> Result<(), Error> {
    let req: resmng::GetInfoReq = is.pop()?;

    let idx = match req.idx {
        usize::MAX => None,
        n => Some(n),
    };

    childs::get_info(id, idx).and_then(|info| reply_vmsg!(is, Code::Success, info))
}

fn quote(is: &mut GateIStream<'_>, id: Id) -> Result<(), Error> {
    static SIG: LazyStaticRefCell<sig::Sig> = LazyStaticRefCell::default();
    if !SIG.is_some() {
        SIG.set(sig::Sig::new("sig")?);
    }

    let mut childs = childs::borrow_mut();
    let child = childs.child_by_id_mut(id).unwrap();

    // TODO this is not final. what app hash to use? how to obtain the cfg hash?
    let quote = SIG
        .borrow()
        .quote(child.cfg().hash().unwrap_or(&String::new()), "")?;
    reply_vmsg!(is, Code::Success, resmng::QuoteReply { quote })
}
