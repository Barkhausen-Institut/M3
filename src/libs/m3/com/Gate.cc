/*
 * Copyright (C) 2015-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
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
#include <m3/com/Gate.h>
#include <m3/tiles/OwnActivity.h>

namespace m3 {

Gate::~Gate() {
    release_ep(Activity::own());
}

const EP &Gate::acquire_ep() {
    if(!_ep)
        _ep = Activity::own().epmng().acquire();
    return *_ep;
}

const EP &Gate::activate(capsel_t rbuf_mem, goff_t rbuf_off) {
    if(!_ep) {
        _ep = Activity::own().epmng().acquire();
        activate_on(*_ep, rbuf_mem, rbuf_off);
    }
    return *_ep;
}

void Gate::activate_on(const EP &ep, capsel_t rbuf_mem, goff_t rbuf_off) {
    Syscalls::activate(ep.sel(), sel(), rbuf_mem, rbuf_off);
}

void Gate::deactivate() {
    release_ep(Activity::own(), true);
}

void Gate::release_ep(OwnActivity &act, bool force_inval) noexcept {
    if(_ep && !_ep->is_standard()) {
        act.epmng().release(_ep, force_inval || (flags() & KEEP_CAP));
        _ep = nullptr;
    }
}

}
