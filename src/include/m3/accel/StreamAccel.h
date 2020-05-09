/*
 * Copyright (C) 2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <m3/com/MemGate.h>
#include <m3/com/SendGate.h>
#include <m3/com/RecvGate.h>
#include <m3/vfs/GenericFile.h>
#include <m3/pes/VPE.h>

#include <memory>

namespace m3 {

class StreamAccel {
    struct Context {
        uint16_t bufOff;
        uint16_t flags;
        uint32_t masks;
        uint64_t compTime;
        uint64_t msgAddr;
        uint64_t inReqAddr;
        uint64_t outReqAddr;
        uint64_t commitOff;
        uint64_t commitLen;
        uint64_t inOff;
        uint64_t inPos;
        uint64_t inLen;
        uint64_t outOff;
        uint64_t outPos;
        uint64_t outLen;
        uint64_t lastSize;
        uint64_t nextSysc;
        uint64_t : 64;
    } PACKED;

public:
    static const size_t MSG_SIZE    = 64;
    static const size_t RB_SIZE     = MSG_SIZE * 4;

    static const epid_t EP_IN_SEND  = 16;
    static const epid_t EP_IN_MEM   = 17;
    static const epid_t EP_OUT_SEND = 18;
    static const epid_t EP_OUT_MEM  = 19;
    static const epid_t EP_RECV     = 20;

    static const uint64_t LBL_IN_REQ    = 1;
    static const uint64_t LBL_IN_REPLY  = 2;
    static const uint64_t LBL_OUT_REQ   = 3;
    static const uint64_t LBL_OUT_REPLY = 4;

    static const size_t BUF_ADDR    = 0x8000;
    static const size_t BUF_SIZE    = 8192;
    static const size_t RECV_ADDR   = 0x1FFF00;

    explicit StreamAccel(std::unique_ptr<VPE> &vpe, cycles_t /* TODO */)
        : _sgate_in(),
          _sgate_out(),
          _mgate_out(),
          _rgate(RecvGate::create(getnextlog2(RB_SIZE), getnextlog2(MSG_SIZE))),
          _in_sep(vpe->epmng().acquire(EP_IN_SEND)),
          _in_mep(vpe->epmng().acquire(EP_IN_MEM)),
          _out_sep(vpe->epmng().acquire(EP_OUT_SEND)),
          _out_mep(vpe->epmng().acquire(EP_OUT_MEM)),
          _rep(vpe->epmng().acquire(EP_RECV, _rgate.slots())),
          _vpe(vpe),
          _mem(_vpe->get_mem(0, vpe->pe_desc().mem_size(), MemGate::RW)) {
        // activate EPs
        _rgate.activate_on(*_rep, nullptr, RECV_ADDR);
    }

    void connect_input(GenericFile *file) {
        connect_file(file, *_in_sep, *_in_mep);
    }
    void connect_input(StreamAccel *prev) {
        _sgate_in = std::make_unique<SendGate>(
            SendGate::create(&prev->_rgate, SendGateArgs().label(LBL_IN_REQ)
                                                          .credits(1))
        );
        _sgate_in->activate_on(*_in_sep);
    }

    void connect_output(GenericFile *file) {
        connect_file(file, *_out_sep, *_out_mep);
    }
    void connect_output(StreamAccel *next) {
        _sgate_out = std::make_unique<SendGate>(
            SendGate::create(&next->_rgate, SendGateArgs().label(LBL_OUT_REQ)
                                                          .credits(1))
        );
        _sgate_out->activate_on(*_out_sep);
        _mgate_out = std::make_unique<MemGate>(next->_mem.derive(BUF_ADDR, BUF_SIZE));
        _mgate_out->activate_on(*_out_mep);
    }

private:
    void connect_file(GenericFile *file, EP &sep, EP &mep) {
        file->sgate().activate_on(sep);
        file->sess().delegate_obj(mep.sel());
    }

    std::unique_ptr<SendGate> _sgate_in;
    std::unique_ptr<SendGate> _sgate_out;
    std::unique_ptr<MemGate> _mgate_out;
    RecvGate _rgate;
    std::unique_ptr<EP> _in_sep;
    std::unique_ptr<EP> _in_mep;
    std::unique_ptr<EP> _out_sep;
    std::unique_ptr<EP> _out_mep;
    std::unique_ptr<EP> _rep;
    std::unique_ptr<VPE> &_vpe;
    MemGate _mem;
};

}
