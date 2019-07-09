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

#pragma once

#include <base/Panic.h>

#include <m3/session/ClientSession.h>
#include <m3/com/MemGate.h>
#include <m3/com/SendGate.h>
#include <m3/com/RecvGate.h>

namespace m3 {

class Pager : public ClientSession {
private:
    explicit Pager(VPE &vpe, capsel_t sess)
        : ClientSession(sess, 0),
          _sep(vpe.alloc_ep()),
          _rep(vpe.alloc_ep()),
          _rgate(vpe.pe().has_mmu() ? RecvGate::create_for(vpe, nextlog2<64>::val, nextlog2<64>::val)
                                    : RecvGate::bind(ObjCap::INVALID, 0)),
          _own_sgate(SendGate::bind(obtain(1).start())),
          _child_sgate(SendGate::bind(obtain(1).start())) {
    }

public:
    enum DelOp {
        DATASPACE,
        MEMGATE,
    };

    enum Operation {
        PAGEFAULT,
        CLONE,
        MAP_ANON,
        UNMAP,
        COUNT,
    };

    enum Flags {
        MAP_PRIVATE = 0,
        MAP_SHARED  = 0x2000,
    };

    enum Prot {
        READ    = MemGate::R,
        WRITE   = MemGate::W,
        EXEC    = MemGate::X,
        RW      = READ | WRITE,
        RWX     = READ | WRITE | EXEC,
    };

    explicit Pager(capsel_t sess, capsel_t rgate) noexcept
        : ClientSession(sess),
          _sep(0),
          _rep(0),
          _rgate(RecvGate::bind(rgate, nextlog2<64>::val)),
          _own_sgate(SendGate::bind(obtain(1).start())),
          _child_sgate(SendGate::bind(ObjCap::INVALID)) {
    }
    explicit Pager(VPE &vpe, const String &service)
        : ClientSession(service),
          _sep(vpe.alloc_ep()),
          _rep(vpe.alloc_ep()),
          _rgate(vpe.pe().has_mmu() ? RecvGate::create_for(vpe, nextlog2<64>::val, nextlog2<64>::val)
                                    : RecvGate::bind(ObjCap::INVALID, 0)),
          _own_sgate(SendGate::bind(obtain(1).start())),
          _child_sgate(SendGate::bind(obtain(1).start())) {
    }

    void activate_gates(VPE &vpe) {
        _child_sgate.activate_for(vpe, _sep);

        if(_rgate.sel() != ObjCap::INVALID) {
            // force activation
            _rgate.deactivate();
            _rgate.activate(_rep);
        }
    }

    const SendGate &own_sgate() const noexcept {
        return _own_sgate;
    }
    const SendGate &child_sgate() const noexcept {
        return _child_sgate;
    }

    epid_t sep() const noexcept {
        return _sep;
    }
    epid_t rep() const noexcept {
        return _rep;
    }
    const RecvGate &rgate() const noexcept {
        return _rgate;
    }

    Pager *create_clone(VPE &vpe);
    void clone();
    void pagefault(goff_t addr, uint access);
    void map_anon(goff_t *virt, size_t len, int prot, int flags);
    void map_ds(goff_t *virt, size_t len, int prot, int flags,
                const ClientSession &sess, size_t offset);
    void map_mem(goff_t *virt, MemGate &mem, size_t len, int prot);
    void unmap(goff_t virt);

private:
    epid_t _sep;
    // the receive gate is only necessary for the PF handler in RCTMux. it needs a dedicated one
    // in order to prevent interference with the application
    epid_t _rep;
    RecvGate _rgate;
    SendGate _own_sgate;
    SendGate _child_sgate;
};

}
