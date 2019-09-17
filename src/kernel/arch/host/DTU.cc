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

#include <base/Common.h>
#include <base/PEMux.h>

#include "pes/VPEManager.h"
#include "DTU.h"

#include <signal.h>

namespace kernel {

void DTU::deprivilege(peid_t) {
    // unsupported
}

void DTU::kill_vpe(const VPEDesc &vpe) {
    pid_t pid = VPEManager::get().vpe(vpe.id).pid();
    // if the VPE didn't run, it has no PID yet
    if(pid != 0)
        kill(pid, SIGKILL);
}

cycles_t DTU::get_time() {
    // unsupported
    return 0;
}

void DTU::flush_cache(const VPEDesc &) {
    // nothing to do
}

void DTU::wakeup(const VPEDesc &) {
    // nothing to do
}

void DTU::suspend(const VPEDesc &) {
    // nothing to do
}

void DTU::inject_irq(const VPEDesc &) {
    // unsupported
}

void DTU::inv_reply_remote(const VPEDesc &, epid_t, peid_t, epid_t) {
    // unused
}

m3::Errors::Code DTU::inval_ep_remote(const VPEDesc &vpe, epid_t ep, bool) {
    word_t regs[m3::DTU::EPS_RCNT];
    memset(regs, 0, sizeof(regs));
    // TODO detect if credits are outstanding
    write_ep_remote(vpe, ep, regs);
    return m3::Errors::NONE;
}

void DTU::read_ep_remote(const VPEDesc &vpe, epid_t ep, void *regs) {
    uintptr_t eps = static_cast<uintptr_t>(VPEManager::get().vpe(vpe.id).eps_base());
    uintptr_t addr = eps + ep * m3::DTU::EPS_RCNT * sizeof(word_t);
    read_mem(vpe, addr, regs, m3::DTU::EPS_RCNT * sizeof(word_t));
}

void DTU::write_ep_remote(const VPEDesc &vpe, epid_t ep, void *regs) {
    uintptr_t eps = static_cast<uintptr_t>(VPEManager::get().vpe(vpe.id).eps_base());
    uintptr_t addr = eps + ep * m3::DTU::EPS_RCNT * sizeof(word_t);
    write_mem(vpe, addr, regs, m3::DTU::EPS_RCNT * sizeof(word_t));
}

void DTU::write_ep_local(epid_t ep) {
    uintptr_t eps = reinterpret_cast<uintptr_t>(m3::DTU::get().ep_regs());
    uintptr_t addr = eps + ep * m3::DTU::EPS_RCNT * sizeof(word_t);
    memcpy(reinterpret_cast<void*>(addr), _state.get_ep(ep), m3::DTU::EPS_RCNT * sizeof(word_t));
}

void DTU::mark_read_remote(const VPEDesc &, epid_t, goff_t) {
    // not supported
}

void DTU::recv_msgs(epid_t ep, uintptr_t buf, int order, int msgorder) {
    _state.config_recv(ep, buf, order, msgorder, 0);
    write_ep_local(ep);
}

void DTU::reply(epid_t ep, const void *reply, size_t size, const m3::DTU::Message *msg) {
    m3::DTU::get().reply(ep, reply, size, msg);
}

m3::Errors::Code DTU::send_to(const VPEDesc &vpe, epid_t ep, label_t label, const void *msg,
                              size_t size, label_t replylbl, epid_t replyep) {
    const size_t msg_ord = static_cast<uint>(m3::getnextlog2(size + m3::DTU::HEADER_SIZE));
    m3::DTU::get().configure(_ep, label, vpe.pe, ep, 1UL << msg_ord, msg_ord);
    return m3::DTU::get().send(_ep, msg, size, replylbl, replyep);
}

m3::Errors::Code DTU::try_write_mem(const VPEDesc &vpe, goff_t addr, const void *data, size_t size) {
    m3::DTU::get().configure(_ep, addr | m3::KIF::Perm::RWX, vpe.pe, 0, size, 0);
    m3::DTU::get().write(_ep, data, size, 0, 0);
    return m3::Errors::NONE;
}

m3::Errors::Code DTU::try_read_mem(const VPEDesc &vpe, goff_t addr, void *data, size_t size) {
    m3::DTU::get().configure(_ep, addr | m3::KIF::Perm::RWX, vpe.pe, 0, size, 0);
    m3::DTU::get().read(_ep, data, size, 0, 0);
    return m3::Errors::NONE;
}

void DTU::copy_clear(const VPEDesc &, goff_t, const VPEDesc &, goff_t, size_t, bool) {
    // not supported
}

void DTU::write_swstate(const VPEDesc &, uint64_t, uint64_t) {
}

void DTU::write_swflags(const VPEDesc &, uint64_t) {
}

void DTU::read_swflags(const VPEDesc &, uint64_t *flags) {
    // we are always immediately finished here
    *flags = m3::PEMuxCtrl::SIGNAL;
}

}
