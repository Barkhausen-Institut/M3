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

#include <m3/session/ResMng.h>
#include <m3/tiles/Activity.h>
#include <m3/tiles/OwnActivity.h>
#include <m3/Syscalls.h>

namespace m3 {

Activity::Activity(capsel_t sel, uint flags,
                   Reference<class Tile> tile, Reference<KMem> kmem, ResMng *resmng)
    : ObjCap(ACTIVITY, sel, flags),
      _id(),
      _next_sel(KIF::FIRST_FREE_SEL),
      _tile(tile),
      _kmem(kmem),
      _eps_start(),
      _pager(),
      _resmng(resmng) {
}

Activity::~Activity() {
}

OwnActivity &Activity::own() noexcept {
    return OwnActivity::_self;
}

void Activity::revoke(const KIF::CapRngDesc &crd, bool delonly) {
    Syscalls::revoke(sel(), crd, !delonly);
}

MemGate Activity::get_mem(goff_t addr, size_t size, int perms) {
    capsel_t nsel = Activity::own().alloc_sel();
    Syscalls::create_mgate(nsel, sel(), addr, size, perms);
    return MemGate::bind(nsel, 0);
}

}
