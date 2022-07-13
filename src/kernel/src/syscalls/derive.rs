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

use base::build_vmsg;
use base::col::ToString;
use base::errors::{Code, Error, VerboseError};
use base::kif::{self, syscalls};
use base::mem::{GlobAddr, MsgBuf};
use base::rc::Rc;
use base::serialize::M3Deserializer;
use base::tcu;

use crate::cap::{Capability, KObject};
use crate::cap::{EPQuota, KMemObject, MGateObject, ServObject, TileObject};
use crate::com::Service;
use crate::ktcu;
use crate::mem;
use crate::syscalls::{get_request, reply_success};
use crate::tiles::{tilemng, Activity, TileMux};

#[inline(never)]
pub fn derive_tile_async(
    act: &Rc<Activity>,
    msg: &'static tcu::Message,
) -> Result<(), VerboseError> {
    let r: syscalls::DeriveTile = get_request(msg)?;
    sysc_log!(
        act,
        "derive_tile(tile={}, dst={}, eps={:?}, bw={:?}, time={:?}, pts={:?})",
        r.tile,
        r.dst,
        r.eps,
        r.bw,
        r.time,
        r.pts,
    );

    if !act.obj_caps().borrow().unused(r.dst) {
        sysc_err!(Code::InvArgs, "Selector {} already in use", r.dst);
    }

    let tile = get_kobj!(act, r.tile, Tile);

    let ep_quota = if let Some(eps) = r.eps {
        if !tile.has_quota(eps) {
            sysc_err!(Code::NoSpace, "Insufficient EPs");
        }
        tile.alloc_eps(eps);

        EPQuota::new(eps)
    }
    else {
        tile.ep_quota().clone()
    };

    let (time_id, pt_id) = if r.time.is_some() || r.pts.is_some() {
        let tilemux = tilemng::tilemux(tile.tile());
        match TileMux::derive_quota_async(
            tilemux,
            tile.time_quota_id(),
            tile.pt_quota_id(),
            r.time,
            r.pts,
        ) {
            Err(e) => {
                if let Some(eps) = r.eps {
                    tile.free_eps(eps);
                }
                return Err(VerboseError::from(e));
            },
            Ok(v) => v,
        }
    }
    else {
        (tile.time_quota_id(), tile.pt_quota_id())
    };

    let bw_quota = if let Some(bw) = r.bw {
        let new_bw = tile.bw_quota().derive(bw)?;

        ktcu::set_memory_bandwidth(tile.tile(), tile.bw_quota()).unwrap();
        ktcu::set_memory_bandwidth(tile.tile(), &new_bw).unwrap();

        new_bw
    }
    else {
        tile.bw_quota().clone()
    };

    let cap = Capability::new(
        r.dst,
        KObject::Tile(TileObject::new(
            tile.tile(),
            ep_quota,
            bw_quota,
            time_id,
            pt_id,
            true,
        )),
    );
    // TODO we will leak the quota object in TileMux if this fails
    try_kmem_quota!(act.obj_caps().borrow_mut().insert_as_child(cap, r.tile));

    reply_success(msg);
    Ok(())
}

#[inline(never)]
pub fn derive_kmem(act: &Rc<Activity>, msg: &'static tcu::Message) -> Result<(), VerboseError> {
    let r: syscalls::DeriveKMem = get_request(msg)?;
    sysc_log!(
        act,
        "derive_kmem(kmem={}, dst={}, quota={:#x})",
        r.kmem,
        r.dst,
        r.quota
    );

    if !act.obj_caps().borrow().unused(r.dst) {
        sysc_err!(Code::InvArgs, "Selector {} already in use", r.dst);
    }

    let kmem = get_kobj!(act, r.kmem, KMem);
    if !kmem.has_quota(r.quota) {
        sysc_err!(Code::NoSpace, "Insufficient quota");
    }

    let cap = Capability::new(r.dst, KObject::KMem(KMemObject::new(r.quota)));
    try_kmem_quota!(act.obj_caps().borrow_mut().insert_as_child(cap, r.kmem));
    assert!(kmem.alloc(act, r.kmem, r.quota));

    reply_success(msg);
    Ok(())
}

#[inline(never)]
pub fn derive_mem(act: &Rc<Activity>, msg: &'static tcu::Message) -> Result<(), VerboseError> {
    let r: syscalls::DeriveMem = get_request(msg)?;
    sysc_log!(
        act,
        "derive_mem(act={}, src={}, dst={}, size={:#x}, offset={:#x}, perms={:?})",
        r.act,
        r.src,
        r.dst,
        r.size,
        r.offset,
        r.perms
    );

    let tact = get_kobj!(act, r.act, Activity).upgrade().unwrap();
    if !tact.obj_caps().borrow().unused(r.dst) {
        sysc_err!(Code::InvArgs, "Selector {} already in use", r.dst);
    }

    let cap = {
        let act_caps = act.obj_caps().borrow();
        let mgate = get_kobj_ref!(act_caps, r.src, MGate);
        if r.offset.checked_add(r.size).is_none() || r.offset + r.size > mgate.size() || r.size == 0
        {
            sysc_err!(Code::InvArgs, "Size or offset invalid");
        }

        let addr = mgate.addr().raw() + r.offset as u64;
        let new_mem = mem::Allocation::new(GlobAddr::new(addr), r.size);
        let mgate_obj = MGateObject::new(new_mem, r.perms & mgate.perms(), true);
        Capability::new(r.dst, KObject::MGate(mgate_obj))
    };

    try_kmem_quota!(tact.obj_caps().borrow_mut().insert_as_child(cap, r.src));

    reply_success(msg);
    Ok(())
}

#[inline(never)]
pub fn derive_srv_async(
    act: &Rc<Activity>,
    msg: &'static tcu::Message,
) -> Result<(), VerboseError> {
    let r: syscalls::DeriveSrv = get_request(msg)?;
    sysc_log!(
        act,
        "derive_srv(dst={}, srv={}, sessions={}, event={})",
        r.dst,
        r.srv,
        r.sessions,
        r.event
    );

    if !act.obj_caps().borrow().range_unused(&r.dst) {
        sysc_err!(Code::InvArgs, "Selectors {} already in use", r.dst);
    }
    if r.sessions == 0 {
        sysc_err!(Code::InvArgs, "Invalid session count");
    }

    let srvcap = get_kobj!(act, r.srv, Serv);

    // everything worked, send the reply
    reply_success(msg);

    let mut smsg = MsgBuf::borrow_def();
    build_vmsg!(smsg, kif::service::Request::DeriveCrt {
        sessions: r.sessions
    });

    let label = srvcap.creator() as tcu::Label;
    klog!(
        SERV,
        "Sending DERIVE_CRT(sessions={}) to service {} with creator {}",
        r.sessions,
        srvcap.service().name(),
        label,
    );
    let res = Service::send_receive_async(srvcap.service(), label, smsg);

    let res = match res {
        Err(e) => {
            sysc_log!(
                act,
                "Service {} unreachable: {:?}",
                srvcap.service().name(),
                e.code()
            );
            Err(e)
        },

        Ok(rmsg) => {
            let mut de = M3Deserializer::new(rmsg.as_words());
            let err: Code = de.pop()?;
            match err {
                Code::None => {
                    let reply: kif::service::DeriveCreatorReply = de.pop()?;

                    sysc_log!(act, "derive_srv continue with creator={}", reply.creator);

                    // obtain SendGate from server (do that first because it can fail)
                    let serv_act = srvcap.service().activity();
                    let mut serv_caps = serv_act.obj_caps().borrow_mut();
                    let src_cap = serv_caps.get_mut(reply.sgate_sel);
                    match src_cap {
                        None => {
                            sysc_log!(act, "Service gave invalid SendGate cap {}", reply.sgate_sel)
                        },
                        Some(c) => try_kmem_quota!(act.obj_caps().borrow_mut().obtain(
                            r.dst.start() + 1,
                            c,
                            true
                        )),
                    }

                    // derive new service object
                    let cap = Capability::new(
                        r.dst.start() + 0,
                        KObject::Serv(ServObject::new(
                            srvcap.service().clone(),
                            false,
                            reply.creator,
                        )),
                    );
                    try_kmem_quota!(act.obj_caps().borrow_mut().insert_as_child(cap, r.srv));
                    Ok(())
                },
                err => {
                    sysc_log!(
                        act,
                        "Server {} denied derive: {:?}",
                        srvcap.service().name(),
                        err
                    );
                    Err(Error::new(err))
                },
            }
        },
    };

    act.upcall_derive_srv(r.event, res);
    Ok(())
}
