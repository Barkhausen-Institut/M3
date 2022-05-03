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

#include <m3/Syscalls.h>
#include <m3/com/EPMng.h>
#include <m3/tiles/Activity.h>

namespace m3 {

EP *EPMng::acquire(epid_t ep, uint replies) {
    EP *e = nullptr;
    if(ep == TOTAL_EPS && replies == 0)
        e = _eps.remove_first();
    if(!e)
        e = new EP(EP::alloc_for(_act, ep, replies));
    return e;
}

void EPMng::release(EP *ep, bool invalidate) noexcept {
    if(invalidate) {
        try {
            // invalidate our endpoint to be able to reuse it for something else later
            Syscalls::activate(ep->sel(), ObjCap::INVALID, ObjCap::INVALID, 0);
        }
        catch(...) {
            // ignore errors here
        }
    }

    if(ep->replies() == 0 && ep->sel() != ObjCap::INVALID)
        _eps.append(ep);
    else
        delete ep;
}

}
