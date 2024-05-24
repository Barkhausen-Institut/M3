/*
 * Copyright (C) 2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <m3/com/MemGate.h>
#include <m3/com/RecvGate.h>
#include <m3/com/SendGate.h>
#include <m3/tiles/ChildActivity.h>
#include <m3/vfs/GenericFile.h>

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
    static const size_t MSG_SIZE = 64;
    static const size_t RB_SIZE = MSG_SIZE * 4;

    static const epid_t EP_IN_SEND = 16;
    static const epid_t EP_IN_MEM = 17;
    static const epid_t EP_OUT_SEND = 18;
    static const epid_t EP_OUT_MEM = 19;
    static const epid_t EP_RECV = 20;

    static const uint64_t LBL_IN_REQ = 1;
    static const uint64_t LBL_IN_REPLY = 2;
    static const uint64_t LBL_OUT_REQ = 3;
    static const uint64_t LBL_OUT_REPLY = 4;

    static const size_t BUF_ADDR = 0x8000;
    static const size_t BUF_SIZE = 8192;
    static const size_t RECV_ADDR = 0x3F'FF00;

    explicit StreamAccel(std::unique_ptr<ChildActivity> &act, CycleDuration /* TODO */)
        : _sgate_in(),
          _sgate_out(),
          _mgate_out(),
          _rcap(RecvCap::create(getnextlog2(RB_SIZE), getnextlog2(MSG_SIZE))),
          _in_sep(EP::alloc_for(act->sel(), EP_IN_SEND)),
          _in_mep(EP::alloc_for(act->sel(), EP_IN_MEM)),
          _out_sep(EP::alloc_for(act->sel(), EP_OUT_SEND)),
          _out_mep(EP::alloc_for(act->sel(), EP_OUT_MEM)),
          _rep(EP::alloc_for(act->sel(), EP_RECV, _rcap.slots())),
          _act(act),
          _mem(_act->get_mem(act->tile_desc().mem_offset(), act->tile_desc().mem_size(),
                             MemGate::RW)) {
        // activate EPs
        _rcap.activate_on(_rep, nullptr, act->tile_desc().mem_offset() + RECV_ADDR);
    }

    void connect_input(GenericFile *file) {
        file->connect(_in_sep, _in_mep);
    }
    void connect_input(StreamAccel *prev) {
        _sgate_in = std::make_unique<SendCap>(
            SendCap::create(&prev->_rcap, SendGateArgs().label(LBL_IN_REQ).credits(1)));
        _sgate_in->activate_on(_in_sep);
    }

    void connect_output(GenericFile *file) {
        file->connect(_out_sep, _out_mep);
    }
    void connect_output(StreamAccel *next) {
        _sgate_out = std::make_unique<SendCap>(
            SendCap::create(&next->_rcap, SendGateArgs().label(LBL_OUT_REQ).credits(1)));
        _sgate_out->activate_on(_out_sep);
        _mgate_out = std::make_unique<MemCap>(next->_mem.derive(BUF_ADDR, BUF_SIZE));
        _mgate_out->activate_on(_out_mep);
    }

private:
    std::unique_ptr<SendCap> _sgate_in;
    std::unique_ptr<SendCap> _sgate_out;
    std::unique_ptr<MemCap> _mgate_out;
    RecvCap _rcap;
    EP _in_sep;
    EP _in_mep;
    EP _out_sep;
    EP _out_mep;
    EP _rep;
    std::unique_ptr<ChildActivity> &_act;
    MemCap _mem;
};

}
