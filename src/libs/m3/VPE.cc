/*
 * Copyright (C) 2016-2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <base/Init.h>
#include <base/Panic.h>

#include <m3/session/Pager.h>
#include <m3/session/ResMng.h>
#include <m3/stream/Standard.h>
#include <m3/vfs/FileTable.h>
#include <m3/vfs/MountTable.h>
#include <m3/vfs/SerialFile.h>
#include <m3/vfs/VFS.h>
#include <m3/Syscalls.h>
#include <m3/VPE.h>

namespace m3 {

const size_t VPE::BUF_SIZE    = 4096;
INIT_PRIO_VPE VPE VPE::_self;

VPEGroup::VPEGroup() : ObjCap(ObjCap::VPEGRP) {
    capsel_t dst = VPE::self().alloc_sel();
    Syscalls::get().createvpegrp(dst);
    sel(dst);
}

size_t KMem::quota() const {
    size_t amount = 0;
    Syscalls::get().kmemquota(sel(), amount);
    return amount;
}

Reference<KMem> KMem::derive(const KMem &base, size_t quota) {
    capsel_t sel = VPE::self().alloc_sel();
    Syscalls::get().derivekmem(base.sel(), sel, quota);
    return Reference<KMem>(new KMem(sel, 0));
}

VPEArgs::VPEArgs()
    : _flags(0),
      _pedesc(VPE::self().pe()),
      _pager(nullptr),
      _rmng(nullptr),
      _group(nullptr),
      _kmem() {
}

// don't revoke these. they kernel does so on exit
VPE::VPE()
    : ObjCap(VIRTPE, 0, KEEP_CAP),
      _pe(env()->pedesc),
      _mem(MemGate::bind(1)),
      _resmng(nullptr),
      _next_sel(KIF::FIRST_FREE_SEL),
      _eps(),
      _pager(),
      _kmem(),
      _rbufcur(),
      _rbufend(),
      _ms(),
      _fds(),
      _exec() {
    static_assert(EP_COUNT <= 64, "64 endpoints are the maximum due to the 64-bit bitmask");
    init_state();
    init_fs();

    if(!_ms)
        _ms = new MountTable();
    if(!_fds)
        _fds = new FileTable();

    // create stdin, stdout and stderr, if not existing
    if(!_fds->exists(STDIN_FD))
        _fds->set(STDIN_FD, Reference<File>(new SerialFile()));
    if(!_fds->exists(STDOUT_FD))
        _fds->set(STDOUT_FD, Reference<File>(new SerialFile()));
    if(!_fds->exists(STDERR_FD))
        _fds->set(STDERR_FD, Reference<File>(new SerialFile()));
}

VPE::VPE(const String &name, const VPEArgs &args)
    : ObjCap(VIRTPE, VPE::self().alloc_sels(KIF::FIRST_FREE_SEL)),
      _pe(args._pedesc),
      _mem(MemGate::bind(sel() + 1, 0)),
      _resmng(args._rmng),
      _next_sel(KIF::FIRST_FREE_SEL),
      _eps(),
      _pager(),
      _kmem(args._kmem ? args._kmem : VPE::self().kmem()),
      _rbufcur(),
      _rbufend(),
      _ms(new MountTable()),
      _fds(new FileTable()),
      _exec() {
    // create pager first, to create session and obtain gate cap
    if(_pe.has_virtmem()) {
        if(args._pager)
            _pager = new Pager(*this, args._pager);
        else if(VPE::self().pager())
            _pager = VPE::self().pager()->create_clone(*this);
        if(Errors::last != Errors::NONE)
            return;
    }

    capsel_t group_sel = args._group ? args._group->sel() : ObjCap::INVALID;
    KIF::CapRngDesc dst(KIF::CapRngDesc::OBJ, sel(), KIF::FIRST_FREE_SEL);
    if(_pager) {
        // now create VPE, which implicitly obtains the gate cap from us
        Syscalls::get().createvpe(dst, _pager->child_sgate().sel(), name, _pe,
            _pager->sep(), _pager->rep(), args._flags, _kmem->sel(), group_sel);
        // mark the send gate cap allocated
        _next_sel = Math::max(_pager->child_sgate().sel() + 1, _next_sel);
        // now delegate our VPE cap and memory cap to the pager
        _pager->delegate(KIF::CapRngDesc(KIF::CapRngDesc::OBJ, sel(), 2));
        // and delegate the pager cap to the VPE
        delegate_obj(_pager->sel());
    }
    else {
        Syscalls::get().createvpe(dst, ObjCap::INVALID, name, _pe,
            0, 0, args._flags, _kmem->sel(), group_sel);
    }
    _next_sel = Math::max(_kmem->sel() + 1, _next_sel);

    if(_resmng == nullptr) {
        _resmng = VPE::self().resmng().clone(*this, name);
        // ensure that the child's cap space is not further ahead than ours
        // TODO improve that
        VPE::self()._next_sel = Math::max(_next_sel, VPE::self()._next_sel);
    }
    else
        delegate_obj(_resmng->sel());
}

VPE::~VPE() {
    if(this != &_self) {
        delete _resmng;
        stop();
        delete _pager;
        // unarm it first. we can't do that after revoke (which would be triggered by the Gate destructor)
        EPMux::get().remove(&_mem, true);
        // only free that if it's not our own VPE. 1. it doesn't matter in this case and 2. it might
        // be stored not on the heap but somewhere else
        delete _fds;
        delete _ms;
        delete _exec;
    }
}

epid_t VPE::alloc_ep() {
    for(epid_t ep = DTU::FIRST_FREE_EP; ep < EP_COUNT; ++ep) {
        if(is_ep_free(ep)) {
            // invalidate the EP if necessary and possible
            if(this == &VPE::self() && !EPMux::get().reserve(ep))
                continue;

            _eps |= static_cast<uint64_t>(1) << ep;
            return ep;
        }
    }

    return 0;
}

void VPE::mounts(const MountTable &ms) {
    delete _ms;
    _ms = new MountTable(ms);
}

Errors::Code VPE::obtain_mounts() {
    return _ms->delegate(*this);
}

void VPE::fds(const FileTable &fds) {
    delete _fds;
    _fds = new FileTable(fds);
}

Errors::Code VPE::obtain_fds() {
    return _fds->delegate(*this);
}

Errors::Code VPE::delegate(const KIF::CapRngDesc &crd, capsel_t dest) {
    Errors::Code res = Syscalls::get().exchange(sel(), crd, dest, false);
    if(res == Errors::NONE)
        _next_sel = Math::max(_next_sel, dest + crd.count());
    return res;
}

Errors::Code VPE::obtain(const KIF::CapRngDesc &crd) {
    return obtain(crd, VPE::self().alloc_sels(crd.count()));
}

Errors::Code VPE::obtain(const KIF::CapRngDesc &crd, capsel_t dest) {
    KIF::CapRngDesc own(crd.type(), dest, crd.count());
    return Syscalls::get().exchange(sel(), own, crd.start(), true);
}

Errors::Code VPE::revoke(const KIF::CapRngDesc &crd, bool delonly) {
    return Syscalls::get().revoke(sel(), crd, !delonly);
}

Errors::Code VPE::start() {
    return Syscalls::get().vpectrl(sel(), KIF::Syscall::VCTRL_START, 0);
}

Errors::Code VPE::stop() {
    return Syscalls::get().vpectrl(sel(), KIF::Syscall::VCTRL_STOP, 0);
}

int VPE::wait_async(event_t event) {
    capsel_t _sel;
    int exitcode;
    const capsel_t sels[] = {sel()};
    Syscalls::get().vpewait(sels, 1, event, &_sel, &exitcode);
    return exitcode;
}

int VPE::wait() {
    return wait_async(0);
}

}
