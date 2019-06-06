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

#include <m3/com/SendGate.h>
#include <m3/Syscalls.h>
#include <m3/VPE.h>

#include <thread/ThreadManager.h>

#include <assert.h>

namespace m3 {

SendGate SendGate::create(RecvGate *rgate, label_t label, word_t credits, RecvGate *replygate, capsel_t sel, uint flags) {
    replygate = replygate == nullptr ? &RecvGate::def() : replygate;
    if(sel == INVALID)
        sel = VPE::self().alloc_sel();
    SendGate gate(sel, flags, replygate);
    Syscalls::create_sgate(gate.sel(), rgate->sel(), label, credits);
    return gate;
}

Errors::Code SendGate::activate_for(VPE &vpe, epid_t ep) {
    return Syscalls::activate(vpe.ep_to_sel(ep), sel(), 0);
}

Errors::Code SendGate::send(const void *data, size_t len, label_t reply_label) {
    Errors::Code res = ensure_activated();
    if(res != Errors::NONE)
        return res;

    res = DTU::get().send(ep(), data, len, reply_label, _replygate->ep());
    if(EXPECT_FALSE(res == Errors::VPE_GONE)) {
        event_t event = ThreadManager::get().get_wait_event();
        res = Syscalls::forward_msg(sel(), _replygate->sel(), data, len, reply_label, event);

        // if this has been done, go to sleep and wait until the kernel sends us the upcall
        if(res == Errors::UPCALL_REPLY) {
            ThreadManager::get().wait_for(event);
            auto *msg = reinterpret_cast<const KIF::Upcall::Forward*>(
                ThreadManager::get().get_current_msg());
            res = static_cast<Errors::Code>(msg->error);
        }
    }

    return res;
}

}
