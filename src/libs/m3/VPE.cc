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

// don't revoke these. they kernel does so on exit
VPE::VPE()
    : ObjCap(VIRTPE, 0, KEEP_CAP),
      _pe(env()->pedesc),
      _mem(MemGate::bind(1)),
      _next_sel(FIRST_FREE_SEL),
      _eps(),
      _pager(),
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

VPE::VPE(const String &name, const PEDesc &pe, const char *pager, uint flags, const VPEGroup *group)
    : ObjCap(VIRTPE, VPE::self().alloc_sels(FIRST_FREE_SEL)),
      _pe(pe),
      _mem(MemGate::bind(sel() + 1, 0)),
      _next_sel(FIRST_FREE_SEL),
      _eps(),
      _pager(),
      _rbufcur(),
      _rbufend(),
      _ms(new MountTable()),
      _fds(new FileTable()),
      _exec() {
    // create pager first, to create session and obtain gate cap
    if(_pe.has_virtmem()) {
        if(pager)
            _pager = new Pager(*this, pager);
        else if(VPE::self().pager())
            _pager = VPE::self().pager()->create_clone(*this);
        if(Errors::last != Errors::NONE)
            return;
    }

    capsel_t group_sel = group ? group->sel() : ObjCap::INVALID;
    KIF::CapRngDesc dst(KIF::CapRngDesc::OBJ, sel(), FIRST_FREE_SEL);
    if(_pager) {
        // now create VPE, which implicitly obtains the gate cap from us
        Syscalls::get().createvpe(dst, _pager->child_sgate().sel(), name, _pe,
            _pager->sep(), _pager->rep(), flags, group_sel);
        // mark the send gate cap allocated
        _next_sel = Math::max(_pager->child_sgate().sel() + 1, _next_sel);
        // now delegate our VPE cap and memory cap to the pager
        _pager->delegate(KIF::CapRngDesc(KIF::CapRngDesc::OBJ, sel(), 2));
        // and delegate the pager cap to the VPE
        delegate_obj(_pager->sel());
    }
    else
        Syscalls::get().createvpe(dst, ObjCap::INVALID, name, _pe, 0, 0, flags, group_sel);
}

VPE::~VPE() {
    if(this != &_self) {
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

int VPE::wait() {
    capsel_t _sel;
    int exitcode;
    const capsel_t sels[] = {sel()};
    Syscalls::get().vpewait(sels, 1, &_sel, &exitcode);
    return exitcode;
}

}
