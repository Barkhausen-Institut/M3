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

#include "cap/CapTable.h"
#include "pes/VPEManager.h"

namespace kernel {

VPE &CapTable::vpe() const {
    return VPEManager::get().vpe(_id - 1);
}

void CapTable::revoke_all() {
    Capability *c;
    // TODO it might be better to do that in a different order, because it is more expensive to
    // remove a node that has two childs (it requires a rotate). Thus, it would be better to start
    // with leaf nodes.
    while((c = static_cast<Capability*>(_caps.remove_root())) != nullptr) {
        revoke(c, false);
        // hack for self-referencing VPE capability. we can't dereference it here, because if we
        // force-destruct a VPE, there might be other references, so that it breaks if we decrease
        // the counter (the self-reference did not increase it).
        if(c->sel() == 0)
            static_cast<VPECapability*>(c)->obj.forget();
        delete c;
    }
}

Capability *CapTable::obtain(capsel_t dst, Capability *c) {
    Capability *nc = c;
    if(c) {
        nc = c->clone(this, dst);
        if(nc)
            inherit(c, nc);
    }
    set(dst, nc);
    return nc;
}

void CapTable::inherit(Capability *parent, Capability *child) {
    child->_parent = parent;
    child->_child = nullptr;
    child->_next = parent->_child;
    child->_prev = nullptr;
    if(child->_next)
        child->_next->_prev = child;
    parent->_child = child;
}

void CapTable::revoke_rec(Capability *c, bool revnext) {
    Capability *child = c->child();
    Capability *next = c->next();

    c->revoke();
    c->table()->unset(c->sel());

    if(child)
        revoke_rec(child, true);
    // on the first level, we don't want to revoke siblings
    if(revnext && next)
        revoke_rec(next, true);
}

void CapTable::revoke(Capability *c, bool revnext) {
    if(c->_next)
        c->_next->_prev = c->_prev;
    if(c->_prev)
        c->_prev->_next = c->_next;
    if(c->_parent && c->_parent->_child == c)
        c->_parent->_child = revnext ? nullptr : c->_next;
    revoke_rec(c, revnext);
}

void CapTable::revoke(const m3::KIF::CapRngDesc &crd, bool own) {
    for(capsel_t i = crd.start(), end = crd.start() + crd.count(); i < end; ) {
        Capability *c = get(i);
        i = c ? c->sel() + c->length : i + 1;
        if(c && c->can_revoke()) {
            if(own)
                revoke(c, false);
            else
                revoke(c->_child, true);
        }
    }
}

m3::OStream &operator<<(m3::OStream &os, const CapTable &ct) {
    os << "CapTable[" << ct.id() << "]:\n";
    ct._caps.print(os, false);
    return os;
}

}
