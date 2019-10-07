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

#include <m3/com/GateStream.h>
#include <m3/session/Pager.h>

namespace m3 {

Pager::~Pager() {
    if(_close) {
        try {
            send_receive_vmsg(_own_sgate, CLOSE);
        }
        catch(...) {
            // ignore
        }
    }
}

void Pager::pagefault(goff_t addr, uint access) {
    GateIStream reply = send_receive_vmsg(_own_sgate, PAGEFAULT, addr, access);
    reply.pull_result();
}

void Pager::map_anon(goff_t *virt, size_t len, int prot, int flags) {
    GateIStream reply = send_receive_vmsg(_own_sgate, MAP_ANON, *virt, len, prot, flags);
    reply.pull_result();
    reply >> *virt;
}

void Pager::map_ds(goff_t *virt, size_t len, int prot, int flags, const ClientSession &sess,
                   size_t offset) {
    KIF::ExchangeArgs args;
    args.count = 5;
    args.vals[0] = DelOp::DATASPACE;
    args.vals[1] = *virt;
    args.vals[2] = len;
    args.vals[3] = static_cast<xfer_t>(prot | flags);
    args.vals[4] = offset;
    delegate(KIF::CapRngDesc(KIF::CapRngDesc::OBJ, sess.sel()), &args);
    *virt = args.vals[0];
}

void Pager::map_mem(goff_t *virt, MemGate &mem, size_t len, int prot) {
    KIF::ExchangeArgs args;
    args.count = 4;
    args.vals[0] = DelOp::MEMGATE;
    args.vals[1] = *virt;
    args.vals[2] = len;
    args.vals[3] = static_cast<xfer_t>(prot);
    delegate(KIF::CapRngDesc(KIF::CapRngDesc::OBJ, mem.sel()), &args);
    *virt = args.vals[0];
}

void Pager::unmap(goff_t virt) {
    GateIStream reply = send_receive_vmsg(_own_sgate, UNMAP, virt);
    reply.pull_result();
}

std::unique_ptr<Pager> Pager::create_clone(VPE &vpe) {
    KIF::CapRngDesc caps;
    {
        KIF::ExchangeArgs args;
        // dummy arg to distinguish from the get_sgate operation
        args.count = 1;
        args.vals[0] = 0;
        caps = obtain(1, &args);
    }
    return std::unique_ptr<Pager>(new Pager(vpe, caps.start()));
}

void Pager::clone() {
    GateIStream reply = send_receive_vmsg(_own_sgate, CLONE);
    reply.pull_result();
}

}
