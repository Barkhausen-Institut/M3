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

#pragma once

#include <base/util/Reference.h>
#include <base/Panic.h>

#include <m3/session/ClientSession.h>
#include <m3/com/MemGate.h>
#include <m3/com/SendGate.h>
#include <m3/com/RecvGate.h>

namespace m3 {

class Activity;

class Pager : public RefCounted, public ClientSession {
private:
    explicit Pager(capsel_t sess, bool);

public:
    enum Operation {
        PAGEFAULT,
        INIT,
        ADD_CHILD,
        ADD_SGATE,
        CLONE,
        MAP_ANON,
        MAP_DS,
        MAP_MEM,
        UNMAP,
        CLOSE,
        COUNT,
    };

    enum Flags {
        MAP_PRIVATE = 0,
        MAP_SHARED  = 0x2000,
        MAP_UNINIT  = 0x4000,
        MAP_NOLPAGE = 0x8000,
    };

    enum Prot {
        READ    = MemGate::R,
        WRITE   = MemGate::W,
        EXEC    = MemGate::X,
        RW      = READ | WRITE,
        RWX     = READ | WRITE | EXEC,
    };

    explicit Pager(capsel_t sess);
    ~Pager();

    const SendGate &own_sgate() const noexcept {
        return _own_sgate;
    }

    const SendGate &child_sgate() const noexcept {
        return _child_sgate;
    }
    const RecvGate &child_rgate() const noexcept {
        return _child_rgate;
    }

    void init(Activity &act);

    Reference<Pager> create_clone();
    void clone();
    void pagefault(goff_t addr, uint access);
    void map_anon(goff_t *virt, size_t len, int prot, int flags);
    void map_ds(goff_t *virt, size_t len, int prot, int flags,
                const ClientSession &sess, size_t offset);
    void map_mem(goff_t *virt, MemGate &mem, size_t len, int prot);
    void unmap(goff_t virt);

private:
    capsel_t get_sgate();

    SendGate _own_sgate;
    RecvGate _child_rgate;
    SendGate _child_sgate;
    bool _close;
};

}
