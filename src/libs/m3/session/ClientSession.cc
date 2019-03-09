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

#include <m3/session/ClientSession.h>
#include <m3/session/ResMng.h>
#include <m3/Syscalls.h>
#include <m3/VPE.h>

namespace m3 {

ClientSession::~ClientSession() {
    if(_close && sel() != INVALID) {
        if(VPE::self().resmng().valid()) {
            VPE::self().resmng().close_sess(sel());
            flags(0);
        }
    }
}

void ClientSession::connect(const String &service, xfer_t arg, capsel_t selector) {
    if(selector == INVALID)
        selector = VPE::self().alloc_sel();
    Errors::Code res;

    if(VPE::self().resmng().valid())
        res = VPE::self().resmng().open_sess(selector, service, arg);
    else
        res = Syscalls::get().opensess(selector, service, arg);
    if(res == Errors::NONE)
        sel(selector);
}

Errors::Code ClientSession::delegate_for(VPE &vpe, const KIF::CapRngDesc &crd, KIF::ExchangeArgs *args) {
    return Syscalls::get().delegate(vpe.sel(), sel(), crd, args);
}

Errors::Code ClientSession::obtain_for(VPE &vpe, const KIF::CapRngDesc &crd, KIF::ExchangeArgs *args) {
    vpe.mark_caps_allocated(crd.start(), crd.count());
    return Syscalls::get().obtain(vpe.sel(), sel(), crd, args);
}

}
