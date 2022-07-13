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
use base::cfg;
use base::col::ToString;
use base::errors::{Code, VerboseError};
use base::goff;
use base::kif::{syscalls, CapRngDesc, CapSel, CapType, PageFlags, Perm};
use base::mem::{GlobAddr, MsgBuf};
use base::rc::Rc;
use base::tcu;

use crate::cap::{Capability, KObject, SelRange};
use crate::cap::{
    EPObject, MGateObject, MapObject, RGateObject, SGateObject, SemObject, ServObject, SessObject,
};
use crate::com::Service;
use crate::mem;
use crate::platform;
use crate::syscalls::{get_request, reply_success, send_reply};
use crate::tiles::{tilemng, Activity, ActivityFlags, ActivityMng};

#[inline(never)]
pub fn create_mgate(act: &Rc<Activity>, msg: &'static tcu::Message) -> Result<(), VerboseError> {
    let r: syscalls::CreateMGate = get_request(msg)?;
    sysc_log!(
        act,
        "create_mgate(dst={}, act={}, addr={:#x}, size={:#x}, perms={:?})",
        r.dst,
        r.act,
        r.addr,
        r.size,
        r.perms,
    );

    if !act.obj_caps().borrow().unused(r.dst) {
        sysc_err!(Code::InvArgs, "Selector {} already in use", r.dst);
    }
    if (r.addr & cfg::PAGE_MASK as goff) != 0 || (r.size & cfg::PAGE_MASK as goff) != 0 {
        sysc_err!(
            Code::InvArgs,
            "Virt address and size need to be page-aligned"
        );
    }

    let tgt_act = get_kobj!(act, r.act, Activity).upgrade().unwrap();

    let sel = (r.addr / cfg::PAGE_SIZE as goff) as CapSel;
    let glob = if platform::tile_desc(tgt_act.tile_id()).has_virtmem() {
        let map_caps = tgt_act.map_caps().borrow();
        let map_cap = map_caps
            .get(sel)
            .ok_or_else(|| VerboseError::new(Code::InvArgs, "Invalid capability".to_string()))?;
        let map_obj = as_obj!(map_cap.get(), Map);

        // TODO think about the flags in MapObject again
        let map_perms = Perm::from_bits_truncate(map_obj.flags().bits() as u32);
        if !(r.perms & !Perm::RWX).is_empty() || !(r.perms & !map_perms).is_empty() {
            sysc_err!(Code::NoPerm, "Invalid permissions");
        }

        let pages = (r.size / cfg::PAGE_SIZE as goff) as CapSel;
        let off = (r.addr / cfg::PAGE_SIZE as goff) as CapSel - map_cap.sel();
        if pages == 0 || off + pages > map_cap.len() {
            sysc_err!(Code::InvArgs, "Invalid length");
        }

        let off =
            crate::ktcu::glob_to_phys_remote(tgt_act.tile_id(), map_obj.global(), map_obj.flags())?;
        GlobAddr::new_with(tgt_act.tile_id(), off)
    }
    else {
        if r.size == 0 || r.addr + r.size >= cfg::MEM_CAP_END as goff {
            sysc_err!(Code::InvArgs, "Region empty or out of bounds");
        }

        GlobAddr::new_with(tgt_act.tile_id(), r.addr)
    };

    let mem = mem::Allocation::new(glob, r.size);
    let cap = Capability::new(r.dst, KObject::MGate(MGateObject::new(mem, r.perms, true)));

    if platform::tile_desc(tgt_act.tile_id()).has_virtmem() {
        let map_caps = tgt_act.map_caps().borrow_mut();
        try_kmem_quota!(act
            .obj_caps()
            .borrow_mut()
            .insert_as_child_from(cap, map_caps, sel));
    }
    else {
        try_kmem_quota!(act.obj_caps().borrow_mut().insert_as_child(cap, r.act));
    }

    reply_success(msg);
    Ok(())
}

#[inline(never)]
pub fn create_rgate(act: &Rc<Activity>, msg: &'static tcu::Message) -> Result<(), VerboseError> {
    let r: syscalls::CreateRGate = get_request(msg)?;
    sysc_log!(
        act,
        "create_rgate(dst={}, size={:#x}, msg_size={:#x})",
        r.dst,
        1u32.checked_shl(r.order).unwrap_or(0),
        1u32.checked_shl(r.msg_order).unwrap_or(0)
    );

    let mut act_caps = act.obj_caps().borrow_mut();

    if !act_caps.unused(r.dst) {
        sysc_err!(Code::InvArgs, "Selector {} already in use", r.dst);
    }
    #[allow(clippy::absurd_extreme_comparisons)]
    if r.msg_order.checked_add(r.order).is_none()
        || r.msg_order > r.order
        || r.order - r.msg_order >= 32
        || (1 << (r.order - r.msg_order)) > cfg::MAX_RB_SIZE
    {
        sysc_err!(Code::InvArgs, "Invalid size");
    }

    try_kmem_quota!(act_caps.insert(Capability::new(
        r.dst,
        KObject::RGate(RGateObject::new(r.order, r.msg_order, false)),
    )));

    reply_success(msg);
    Ok(())
}

#[inline(never)]
pub fn create_sgate(act: &Rc<Activity>, msg: &'static tcu::Message) -> Result<(), VerboseError> {
    let r: syscalls::CreateSGate = get_request(msg)?;
    sysc_log!(
        act,
        "create_sgate(dst={}, rgate={}, label={:#x}, credits={})",
        r.dst,
        r.rgate,
        r.label,
        r.credits
    );

    let mut act_caps = act.obj_caps().borrow_mut();

    if !act_caps.unused(r.dst) {
        sysc_err!(Code::InvArgs, "Selector {} already in use", r.dst);
    }

    let cap = {
        let rgate = get_kobj_ref!(act_caps, r.rgate, RGate);
        Capability::new(
            r.dst,
            KObject::SGate(SGateObject::new(rgate, r.label, r.credits)),
        )
    };

    try_kmem_quota!(act_caps.insert_as_child(cap, r.rgate));

    reply_success(msg);
    Ok(())
}

#[inline(never)]
pub fn create_srv(act: &Rc<Activity>, msg: &'static tcu::Message) -> Result<(), VerboseError> {
    let r: syscalls::CreateSrv<'_> = get_request(msg)?;
    sysc_log!(
        act,
        "create_srv(dst={}, rgate={}, creator={}, name={})",
        r.dst,
        r.rgate,
        r.creator,
        r.name
    );

    if !act.obj_caps().borrow().unused(r.dst) {
        sysc_err!(Code::InvArgs, "Selector {} already in use", r.dst);
    }
    if r.name.is_empty() {
        sysc_err!(Code::InvArgs, "Invalid server name");
    }

    let mut act_caps = act.obj_caps().borrow_mut();

    let cap = {
        let rgate = get_kobj_ref!(act_caps, r.rgate, RGate);
        if !rgate.activated() {
            sysc_err!(Code::InvArgs, "RGate is not activated");
        }

        let serv = Service::new(act, r.name.to_string(), rgate.clone());
        Capability::new(r.dst, KObject::Serv(ServObject::new(serv, true, r.creator)))
    };

    try_kmem_quota!(act_caps.insert(cap));

    reply_success(msg);
    Ok(())
}

#[inline(never)]
pub fn create_sess(act: &Rc<Activity>, msg: &'static tcu::Message) -> Result<(), VerboseError> {
    let r: syscalls::CreateSess = get_request(msg)?;
    sysc_log!(
        act,
        "create_sess(dst={}, srv={}, creator={}, ident={:#x}, auto_close={})",
        r.dst,
        r.srv,
        r.creator,
        r.ident,
        r.auto_close
    );

    let mut obj_caps = act.obj_caps().borrow_mut();
    if !obj_caps.unused(r.dst) {
        sysc_err!(Code::InvArgs, "Selector {} already in use", r.dst);
    }

    let serv_cap = get_cap!(obj_caps, r.srv);
    if serv_cap.has_parent() {
        sysc_err!(Code::InvArgs, "Only the service owner can create sessions");
    }

    let serv = as_obj!(serv_cap.get(), Serv);
    // TODO implement auto_close
    let cap = Capability::new(
        r.dst,
        KObject::Sess(SessObject::new(serv, r.creator, r.ident)),
    );

    try_kmem_quota!(obj_caps.insert_as_child(cap, r.srv));

    reply_success(msg);
    Ok(())
}

#[inline(never)]
pub fn create_activity_async(
    act: &Rc<Activity>,
    msg: &'static tcu::Message,
) -> Result<(), VerboseError> {
    let r: syscalls::CreateActivity<'_> = get_request(msg)?;
    sysc_log!(
        act,
        "create_activity(dst={}, name={}, tile={}, kmem={})",
        r.dst,
        r.name,
        r.tile,
        r.kmem
    );

    if !act
        .obj_caps()
        .borrow()
        .range_unused(&CapRngDesc::new(CapType::OBJECT, r.dst, 3))
    {
        sysc_err!(
            Code::InvArgs,
            "Selectors {}..{} already in use",
            r.dst,
            r.dst + 2
        );
    }
    if r.name.is_empty() {
        sysc_err!(Code::InvArgs, "Invalid name");
    }

    let tile = get_kobj!(act, r.tile, Tile);
    if !tile.has_quota(tcu::STD_EPS_COUNT as u32) {
        sysc_err!(
            Code::InvArgs,
            "Tile cap has insufficient EPs (have {}, need {})",
            tile.ep_quota().left(),
            tcu::STD_EPS_COUNT
        );
    }
    // memory-bandwidth = 0 is illegal
    if tile.bw_quota().rate() == 0 {
        sysc_err!(Code::InvArgs, "Tile cap has memory bandwidth of 0");
    }

    let kmem = get_kobj!(act, r.kmem, KMem);
    // TODO kmem quota stuff

    // find contiguous space for standard EPs
    let tile_id = tile.tile();
    let tilemux = tilemng::tilemux(tile_id);
    let eps = match tilemux.find_eps(tcu::STD_EPS_COUNT as u32) {
        Ok(eps) => eps,
        Err(e) => sysc_err!(e.code(), "No free range for standard EPs"),
    };
    if tilemux.has_activities() && !platform::tile_desc(tile.tile()).has_virtmem() {
        sysc_err!(Code::NotSup, "Virtual memory is required for tile sharing");
    }
    drop(tilemux);

    // create activity
    let nact =
        match ActivityMng::create_activity_async(r.name, tile, eps, kmem, ActivityFlags::empty()) {
            Ok(nact) => nact,
            Err(e) => sysc_err!(e.code(), "Unable to create Activity"),
        };

    // give activity cap to the parent
    let cap = Capability::new(r.dst, KObject::Activity(Rc::downgrade(&nact)));
    try_kmem_quota!(act.obj_caps().borrow_mut().insert(cap));

    // create EP caps for the pager EPs
    if nact.tile_desc().has_virtmem() {
        let nact_rc = Rc::downgrade(&nact);
        for (i, ep) in [eps + tcu::PG_SEP_OFF, eps + tcu::PG_REP_OFF]
            .iter()
            .enumerate()
        {
            let scap = Capability::new(
                r.dst + 1 + i as CapSel,
                KObject::EP(EPObject::new(true, nact_rc.clone(), *ep, 0, nact.tile())),
            );
            try_kmem_quota!(act.obj_caps().borrow_mut().insert_as_child(scap, r.dst));
        }
    }

    let mut kreply = MsgBuf::borrow_def();
    build_vmsg!(kreply, Code::None, syscalls::CreateActivityReply {
        id: nact.id(),
        eps_start: eps,
    });
    send_reply(msg, &kreply);

    Ok(())
}

#[inline(never)]
pub fn create_sem(act: &Rc<Activity>, msg: &'static tcu::Message) -> Result<(), VerboseError> {
    let r: syscalls::CreateSem = get_request(msg)?;
    sysc_log!(act, "create_sem(dst={}, value={})", r.dst, r.value);

    if !act.obj_caps().borrow().unused(r.dst) {
        sysc_err!(Code::InvArgs, "Selector {} already in use", r.dst);
    }

    let cap = Capability::new(r.dst, KObject::Sem(SemObject::new(r.value)));
    try_kmem_quota!(act.obj_caps().borrow_mut().insert(cap));

    reply_success(msg);
    Ok(())
}

#[inline(never)]
pub fn create_map_async(
    act: &Rc<Activity>,
    msg: &'static tcu::Message,
) -> Result<(), VerboseError> {
    let r: syscalls::CreateMap = get_request(msg)?;
    sysc_log!(
        act,
        "create_map(dst={}, act={}, mgate={}, first={}, pages={}, perms={:?})",
        r.dst,
        r.act,
        r.mgate,
        r.first,
        r.pages,
        r.perms
    );

    let dst_act = get_kobj!(act, r.act, Activity).upgrade().unwrap();
    if !platform::tile_desc(dst_act.tile_id()).has_virtmem() {
        sysc_err!(Code::InvArgs, "Tile has no virtual-memory support");
    }

    let mgate = get_kobj!(act, r.mgate, MGate);
    if (mgate.addr().raw() & cfg::PAGE_MASK as goff) != 0
        || (mgate.size() & cfg::PAGE_MASK as goff) != 0
    {
        sysc_err!(
            Code::InvArgs,
            "Memory capability is not page aligned (addr={:?}, size={:#x})",
            mgate.addr(),
            mgate.size()
        );
    }
    if (r.perms.bits() & !mgate.perms().bits()) != 0 {
        sysc_err!(Code::InvArgs, "Invalid permissions");
    }

    let total_pages = (mgate.size() >> cfg::PAGE_BITS) as CapSel;
    if r.first.checked_add(r.pages).is_none()
        || r.pages == 0
        || r.first >= total_pages
        || r.first + r.pages > total_pages
    {
        sysc_err!(Code::InvArgs, "Region of memory cap is invalid");
    }

    let virt = (r.dst as goff) << cfg::PAGE_BITS;
    let base = mgate.addr().raw();
    let phys = GlobAddr::new(base + (cfg::PAGE_SIZE * r.first as usize) as u64);

    // retrieve/create map object
    let (map_obj, exists) = {
        let map_caps = dst_act.map_caps().borrow();
        let map_cap: Option<&Capability> = map_caps.get(r.dst);
        match map_cap {
            Some(c) => {
                // TODO check for kernel-created caps
                // TODO we have to update MemGates that are childs of this cap
                if c.len() != r.pages {
                    sysc_err!(Code::InvArgs, "Map cap exists with different page count");
                }

                (c.get().clone(), true)
            },
            None => {
                let range = CapRngDesc::new(CapType::MAPPING, r.dst, r.pages);
                if !map_caps.range_unused(&range) {
                    sysc_err!(Code::InvArgs, "Capability range {} already in use", range);
                }

                let kobj = KObject::Map(MapObject::new(phys, PageFlags::from(r.perms)));
                (kobj, false)
            },
        }
    };

    // create/update the PTEs
    if let KObject::Map(m) = &map_obj {
        if let Err(e) = m.map_async(
            &dst_act,
            virt,
            phys,
            r.pages as usize,
            PageFlags::from(r.perms),
        ) {
            sysc_err!(e.code(), "Unable to map memory");
        }
    }

    // create map cap, if not yet existing
    if !exists {
        let cap = Capability::new_range(SelRange::new_range(r.dst, r.pages), map_obj);
        try_kmem_quota!(dst_act.map_caps().borrow_mut().insert_as_child_from(
            cap,
            act.obj_caps().borrow_mut(),
            r.mgate,
        ));
    }

    reply_success(msg);
    Ok(())
}
