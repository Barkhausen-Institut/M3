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

#include <base/Common.h>
#include <base/DTU.h>

#include "pes/VPE.h"
#include "DTUState.h"
#include "DTU.h"

namespace kernel {

bool DTUState::was_idling() const {
    // not supported
    return false;
}

cycles_t DTUState::get_idle_time() const {
    // not supported
    return 0;
}

void *DTUState::get_ep(epid_t ep) {
    return _regs._eps + ep * m3::DTU::EPS_RCNT;
}

void DTUState::save(const VPEDesc &) {
    // not supported
}

void DTUState::restore(const VPEDesc &, vpeid_t) {
    // not supported
}

void DTUState::invalidate(epid_t ep) {
    memset(get_ep(ep), 0, sizeof(word_t) * m3::DTU::EPS_RCNT);
}

void DTUState::invalidate_eps(epid_t first) {
    size_t total = sizeof(word_t) * m3::DTU::EPS_RCNT * (EP_COUNT - first);
    memset(get_ep(first), 0, total);
}

bool DTUState::can_forward_msg(epid_t) {
    // not supported
    return false;
}

void DTUState::forward_msg(epid_t, peid_t, vpeid_t) {
    // not supported
}

void DTUState::forward_mem(epid_t, peid_t) {
    // not supported
}

void DTUState::read_ep(const VPEDesc &vpe, epid_t ep) {
    DTU::get().read_ep_remote(vpe, ep, get_ep(ep));
}

void DTUState::config_recv(epid_t ep, uintptr_t buf, uint order, uint msgorder) {
    word_t *regs = reinterpret_cast<word_t*>(get_ep(ep));
    regs[m3::DTU::EP_BUF_ADDR]       = buf;
    regs[m3::DTU::EP_BUF_ORDER]      = order;
    regs[m3::DTU::EP_BUF_MSGORDER]   = msgorder;
    regs[m3::DTU::EP_BUF_ROFF]       = 0;
    regs[m3::DTU::EP_BUF_WOFF]       = 0;
    regs[m3::DTU::EP_BUF_MSGCNT]     = 0;
}

void DTUState::config_send(epid_t ep, label_t lbl, peid_t pe, vpeid_t, epid_t dstep, size_t, word_t credits) {
    word_t *regs = reinterpret_cast<word_t*>(get_ep(ep));
    regs[m3::DTU::EP_LABEL]         = lbl;
    regs[m3::DTU::EP_COREID]        = pe;
    regs[m3::DTU::EP_EPID]          = dstep;
    regs[m3::DTU::EP_CREDITS]       = credits;
}

void DTUState::config_mem(epid_t, peid_t, vpeid_t, uintptr_t, size_t, int) {
    // unused
    assert(false);
}

void DTUState::config_rwb(uintptr_t) {
    // not supported
}

void DTUState::config_pf(uint64_t, epid_t) {
    // not supported
}

void DTUState::reset(uintptr_t) {
    // not supported
}

}
