/*
 * Copyright (C) 2015, Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <base/KIF.h>

#include "cap/CapTable.h"
#include "com/Services.h"
#include "pes/VPE.h"
#include "Gate.h"

namespace kernel {

class SyscallHandler {
    explicit SyscallHandler();

public:
    using handler_func = void (SyscallHandler::*)(GateIStream &is);

    static SyscallHandler &get() {
        return _inst;
    }

    void add_operation(m3::KIF::Syscall::Operation op, handler_func func) {
        _callbacks[op] = func;
    }

    void handle_message(GateIStream &msg);

    epid_t epid() const {
        // we can use it here because we won't issue syscalls ourself
        return m3::DTU::SYSC_SEP;
    }
    epid_t srvepid() const {
        return _serv_ep;
    }

    RecvGate create_gate(VPE *vpe) {
        return RecvGate(epid(), vpe);
    }

    void pagefault(GateIStream &is);
    void createsrv(GateIStream &is);
    void createsess(GateIStream &is);
    void createsessat(GateIStream &is);
    void creategate(GateIStream &is);
    void createvpe(GateIStream &is);
    void createmap(GateIStream &is);
    void attachrb(GateIStream &is);
    void detachrb(GateIStream &is);
    void exchange(GateIStream &is);
    void vpectrl(GateIStream &is);
    void delegate(GateIStream &is);
    void obtain(GateIStream &is);
    void activate(GateIStream &is);
    void forwardmsg(GateIStream &is);
    void forwardmem(GateIStream &is);
    void forwardreply(GateIStream &is);
    void reqmem(GateIStream &is);
    void derivemem(GateIStream &is);
    void revoke(GateIStream &is);
    void idle(GateIStream &is);
    void exit(GateIStream &is);
    void noop(GateIStream &is);

#if defined(__host__)
    void init(GateIStream &is);
#endif

private:
    m3::Errors::Code wait_for(const char *name, VPE &tvpe, VPE *cur);
    m3::Errors::Code do_exchange(VPE *v1, VPE *v2, const m3::KIF::CapRngDesc &c1,
        const m3::KIF::CapRngDesc &c2, bool obtain);
    void exchange_over_sess(GateIStream &is, bool obtain);

    epid_t _serv_ep;
    // +1 for init on host
    handler_func _callbacks[m3::KIF::Syscall::COUNT + 1];
    static SyscallHandler _inst;
};

}
