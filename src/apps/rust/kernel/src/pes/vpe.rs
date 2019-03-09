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

use base::col::{String, ToString, Vec};
use base::cell::{Ref, RefCell, RefMut};
use base::cfg;
use base::dtu::{EpId, PEId, HEADER_COUNT, EP_COUNT, FIRST_FREE_EP};
use base::errors::{Code, Error};
use base::GlobAddr;
use base::goff;
use base::kif::{CapRngDesc, CapSel, CapType, FIRST_EP_SEL, PEDesc, Perm};
use base::rc::Rc;
use core::fmt;
use core::mem;
use thread;

use arch::kdtu;
use arch::loader::Loader;
use arch::vm;
use cap::{Capability, CapTable, EPObject, KObject, SGateObject, RGateObject, MGateObject};
use mem::Allocation;
use pes::vpemng;
use platform;

pub type VPEId = usize;

bitflags! {
    pub struct VPEFlags : u32 {
        const BOOTMOD     = 0b00000001;
        const DAEMON      = 0b00000010;
        const IDLE        = 0b00000100;
        const INIT        = 0b00001000;
        const HASAPP      = 0b00010000;
        const MUXABLE     = 0b00100000; // TODO temporary
        const READY       = 0b01000000;
        const WAITING     = 0b10000000;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    RUNNING,
    SUSPENDED,
    DEAD
}

pub const INVALID_VPE: VPEId = 0xFFFF;

static EXIT_EVENT: i32 = 0;

pub struct VPEDesc<'v> {
    pe: PEId,
    vpe_id: VPEId,
    vpe: Option<&'v VPE>,
}

impl<'v> VPEDesc<'v> {
    pub fn new(pe: PEId, vpe: &'v VPE) -> VPEDesc<'v> {
        VPEDesc {
            pe: pe,
            vpe_id: vpe.id(),
            vpe: Some(vpe),
        }
    }
    pub fn new_kernel(vpe_id: VPEId) -> Self {
        VPEDesc {
            pe: platform::kernel_pe(),
            vpe_id: vpe_id,
            vpe: None,
        }
    }
    pub fn new_mem(pe: PEId) -> Self {
        VPEDesc {
            pe: pe,
            vpe_id: INVALID_VPE,
            vpe: None,
        }
    }

    pub fn vpe(&self) -> Option<&VPE> {
        self.vpe
    }
    pub fn pe_id(&self) -> PEId {
        self.pe
    }
    pub fn vpe_id(&self) -> VPEId {
        self.vpe_id
    }
}

pub struct VPE {
    id: VPEId,
    pe: PEId,
    pid: i32,
    state: State,
    name: String,
    flags: VPEFlags,
    obj_caps: CapTable,
    map_caps: CapTable,
    eps_addr: usize,
    args: Vec<String>,
    ep_caps: Vec<Option<CapSel>>,
    exit_code: Option<i32>,
    dtu_state: kdtu::State,
    addr_space: Option<vm::AddrSpace>,
    rbufs_size: usize,
    headers: usize,
}

impl VPE {
    pub fn new(name: &str, id: VPEId, pe: PEId,
               flags: VPEFlags, addr_space: Option<vm::AddrSpace>) -> Rc<RefCell<Self>> {
        let vpe = Rc::new(RefCell::new(VPE {
            id: id,
            pe: pe,
            pid: 0,
            state: State::DEAD,
            name: name.to_string(),
            flags: flags,
            obj_caps: CapTable::new(),
            map_caps: CapTable::new(),
            eps_addr: 0,
            args: Vec::new(),
            ep_caps: vec![None; EP_COUNT - FIRST_FREE_EP],
            exit_code: None,
            dtu_state: kdtu::State::new(),
            addr_space: addr_space,
            rbufs_size: 0,
            headers: 0,
        }));

        {
            let mut vpe_mut = vpe.borrow_mut();
            unsafe {
                vpe_mut.obj_caps.set_vpe(vpe.as_ptr());
                vpe_mut.map_caps.set_vpe(vpe.as_ptr());
            }

            // cap for own VPE
            vpe_mut.obj_caps_mut().insert(
                Capability::new(0, KObject::VPE(vpe.clone()))
            );
            // cap for own memory
            vpe_mut.obj_caps_mut().insert(
                Capability::new(1, KObject::MGate(MGateObject::new(
                    // pretend that it's derived; we don't want to free it
                    id, Allocation::new(GlobAddr::new(0), cfg::MEM_CAP_END), Perm::RWX, true
                )))
            );
            // ep caps
            for ep in FIRST_FREE_EP..EP_COUNT {
                let sel = FIRST_EP_SEL + (ep - FIRST_FREE_EP) as CapSel;
                vpe_mut.obj_caps_mut().insert(
                    Capability::new(sel, KObject::EP(EPObject::new(id, ep)))
                );
            }

            vpe_mut.init();
        }

        vpe
    }

    pub fn destroy(&mut self) {
        self.state = State::DEAD;

        self.obj_caps.revoke_all();
        self.map_caps.revoke_all();
    }

    #[cfg(target_os = "linux")]
    fn init(&mut self) {
    }

    #[cfg(target_os = "none")]
    fn init(&mut self) {
        use base::dtu;
        use base::cfg;
        use pes::vpemng;

        let rgate = RGateObject::new(cfg::SYSC_RBUF_ORD, cfg::SYSC_RBUF_ORD);

        // attach syscall receive endpoint
        {
            let mut rgate = rgate.borrow_mut();
            rgate.order = cfg::SYSC_RBUF_ORD;
            rgate.msg_order = cfg::SYSC_RBUF_ORD;
            rgate.addr = platform::default_rcvbuf(self.pe_id());
            self.config_rcv_ep(dtu::SYSC_REP, &mut rgate).unwrap();
        }

        // attach syscall endpoint
        {
            let mut rgate = rgate.borrow_mut();
            rgate.vpe = vpemng::KERNEL_VPE;
            rgate.ep = Some(kdtu::KSYS_EP);
        }
        let sgate = SGateObject::new(&rgate, self.id() as dtu::Label, cfg::SYSC_RBUF_SIZE as u64);
        self.config_snd_ep(dtu::SYSC_SEP, &sgate.borrow(), platform::kernel_pe()).unwrap();

        // attach upcall receive endpoint
        {
            let mut rgate = rgate.borrow_mut();
            rgate.order = cfg::UPCALL_RBUF_ORD;
            rgate.msg_order = cfg::UPCALL_RBUF_ORD;
            rgate.addr += cfg::SYSC_RBUF_SIZE as goff;
            self.config_rcv_ep(dtu::UPCALL_REP, &mut rgate).unwrap();
        }

        // attach default receive endpoint
        {
            let mut rgate = rgate.borrow_mut();
            rgate.order = cfg::DEF_RBUF_ORD;
            rgate.msg_order = cfg::DEF_RBUF_ORD;
            rgate.addr += cfg::DEF_RBUF_SIZE as goff;
            self.config_rcv_ep(dtu::DEF_REP, &mut rgate).unwrap();
        }

        self.rbufs_size = rgate.borrow().addr as usize + (1 << rgate.borrow().order);
        self.rbufs_size -= platform::default_rcvbuf(self.pe_id()) as usize;

        if !self.is_bootmod() {
            let loader = Loader::get();
            loader.init_app(self).unwrap();
        }
    }

    pub fn id(&self) -> VPEId {
        self.id
    }
    pub fn pe_id(&self) -> PEId {
        self.pe
    }
    pub fn desc(&self) -> VPEDesc {
        VPEDesc::new(self.pe, self)
    }
    pub fn pe_desc(&self) -> PEDesc {
        platform::pe_desc(self.pe_id())
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn args(&self) -> &Vec<String> {
        &self.args
    }

    pub fn addr_space(&self) -> Option<&vm::AddrSpace> {
        self.addr_space.as_ref()
    }

    pub fn obj_caps(&self) -> &CapTable {
        &self.obj_caps
    }
    pub fn obj_caps_mut(&mut self) -> &mut CapTable {
        &mut self.obj_caps
    }

    pub fn map_caps(&self) -> &CapTable {
        &self.map_caps
    }
    pub fn map_caps_mut(&mut self) -> &mut CapTable {
        &mut self.map_caps
    }

    pub fn state(&self) -> State {
        self.state.clone()
    }
    pub fn set_state(&mut self, state: State) {
        self.state = state;
    }

    pub fn dtu_state(&mut self) -> &mut kdtu::State {
        &mut self.dtu_state
    }

    pub fn has_app(&self) -> bool {
        self.flags.contains(VPEFlags::HASAPP)
    }
    pub fn is_bootmod(&self) -> bool {
        self.flags.contains(VPEFlags::BOOTMOD)
    }
    pub fn is_daemon(&self) -> bool {
        self.flags.contains(VPEFlags::DAEMON)
    }
    pub fn make_daemon(&mut self) {
        self.flags |= VPEFlags::DAEMON;
    }
    pub fn add_arg(&mut self, arg: &str) {
        self.args.push(arg.to_string());
    }

    pub fn eps_addr(&self) -> usize {
        self.eps_addr
    }
    pub fn set_eps_addr(&mut self, eps: usize) {
        self.eps_addr = eps;
    }

    pub fn pid(&self) -> i32 {
        self.pid
    }
    pub fn set_pid(&mut self, pid: i32) {
        self.pid = pid;
    }

    pub fn start(&mut self, pid: i32) -> Result<(), Error> {
        self.flags |= VPEFlags::HASAPP;
        self.set_pid(pid);

        let loader = Loader::get();
        let pid = loader.load_app(self)?;
        self.set_pid(pid);
        Ok(())
    }

    pub fn fetch_exit_code(&mut self) -> Option<i32> {
        mem::replace(&mut self.exit_code, None)
    }

    pub fn wait() {
        let event = &EXIT_EVENT as *const _ as thread::Event;
        thread::ThreadManager::get().wait_for(event);
    }

    pub fn stop(vpe: Rc<RefCell<VPE>>, exit_code: i32) {
        if vpe.borrow().flags.contains(VPEFlags::HASAPP) {
            vpe.borrow_mut().flags.remove(VPEFlags::HASAPP);
            vpe.borrow_mut().exit_code = Some(exit_code);

            let event = &EXIT_EVENT as *const _ as thread::Event;
            thread::ThreadManager::get().notify(event, None);

            // if it's a boot module, there is nobody waiting for it; just remove it
            if vpe.borrow().is_bootmod() {
                let id = vpe.borrow().id();
                vpemng::get().remove(id);
            }
        }
    }

    pub fn revoke(vpe: &Rc<RefCell<VPE>>, crd: CapRngDesc, own: bool) {
        // we can't use borrow_mut() here, because revoke might need to use borrow as well.
        unsafe {
            if crd.cap_type() == CapType::OBJECT {
                (*vpe.as_ptr()).obj_caps_mut().revoke(crd, own);
            }
            else {
                (*vpe.as_ptr()).map_caps_mut().revoke(crd, own);
            }
        }
    }

    pub fn ep_with_sel(&self, sel: CapSel) -> Option<EpId> {
        for ep in 0..EP_COUNT - FIRST_FREE_EP {
            match self.ep_caps[ep] {
                Some(s)     => if s == sel { return Some(ep + FIRST_FREE_EP) },
                None        => {},
            }
        }
        None
    }
    pub fn get_ep_sel(&self, ep: EpId) -> Option<CapSel> {
        self.ep_caps[ep - FIRST_FREE_EP].clone()
    }
    pub fn set_ep_sel(&mut self, ep: EpId, sel: Option<CapSel>) {
        self.ep_caps[ep - FIRST_FREE_EP] = sel;
    }

    pub fn config_snd_ep(&mut self, ep: EpId, obj: &Ref<SGateObject>, pe_id: PEId) -> Result<(), Error> {
        let rgate: Ref<RGateObject> = obj.rgate.borrow();
        assert!(rgate.activated());

        klog!(EPS, "VPE{}:EP{} = {:?}", self.id(), ep, obj);

        self.dtu_state.config_send(
            ep, obj.label, pe_id, rgate.vpe, rgate.ep.unwrap(), rgate.msg_size(), obj.credits
        );
        self.update_ep(ep)
    }

    pub fn config_rcv_ep(&mut self, ep: EpId, obj: &mut RefMut<RGateObject>) -> Result<(), Error> {
        // it needs to be in the receive buffer space
        let addr = platform::default_rcvbuf(self.pe_id());
        let size = platform::rcvbufs_size(self.pe_id());

        // default_rcvbuf() == 0 means that we do not validate it
        if addr != 0 && (obj.addr < addr ||
                         obj.addr > addr + size as goff ||
                         obj.addr + obj.size() as goff > addr + size as goff ||
                         obj.addr < addr + self.rbufs_size as goff) {
            return Err(Error::new(Code::InvArgs));
        }

        // no free headers left?
        let msg_slots = 1 << (obj.order - obj.msg_order);
        if self.headers + msg_slots > HEADER_COUNT {
            return Err(Error::new(Code::OutOfMem));
        }

        // TODO really manage the header space and zero the headers first in case they are reused
        obj.header = self.headers;
        self.headers += msg_slots;

        klog!(EPS, "VPE{}:EP{} = {:?}", self.id(), ep, obj);

        self.dtu_state.config_recv(ep, obj.addr, obj.order, obj.msg_order, obj.header);
        self.update_ep(ep)?;

        thread::ThreadManager::get().notify(obj.get_event(), None);

        Ok(())
    }

    pub fn config_mem_ep(&mut self, ep: EpId, obj: &Ref<MGateObject>,
                         pe_id: PEId, off: goff) -> Result<(), Error> {
        if off >= obj.size() as goff || obj.addr() + off < off {
            return Err(Error::new(Code::InvArgs));
        }

        klog!(EPS, "VPE{}:EP{} = {:?}", self.id(), ep, obj);

        // TODO
        self.dtu_state.config_mem(ep, pe_id, obj.vpe, obj.addr() + off,
            obj.size() - off as usize, obj.perms);
        self.update_ep(ep)
    }

    pub fn invalidate_ep(&mut self, ep: EpId, cmd: bool) -> Result<(), Error> {
        klog!(EPS, "VPE{}:EP{} = invalid", self.id(), ep);

        if cmd {
            if self.state == State::RUNNING {
                kdtu::KDTU::get().invalidate_ep_remote(&self.desc(), ep)?;
            }
            else {
                self.dtu_state.invalidate(ep, true)?;
            }
        }
        else {
            self.dtu_state.invalidate(ep, false)?;
            self.update_ep(ep)?;
        }
        Ok(())
    }

    fn update_ep(&mut self, ep: EpId) -> Result<(), Error> {
        if self.state == State::RUNNING {
            kdtu::KDTU::get().write_ep_remote(&self.desc(), ep, self.dtu_state.get_ep(ep))
        }
        else {
            Ok(())
        }
    }
}

impl fmt::Debug for VPE {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VPE[id={}, pe={}, name={}, state={:?}]",
            self.id(), self.pe_id(), self.name(), self.state())
    }
}
