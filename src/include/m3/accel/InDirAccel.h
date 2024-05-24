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

#include <m3/com/GateStream.h>
#include <m3/com/MemGate.h>
#include <m3/com/RecvGate.h>
#include <m3/com/SendGate.h>
#include <m3/tiles/ChildActivity.h>

#include <memory>

namespace m3 {

class InDirAccel {
public:
    static const size_t MSG_SIZE = 64;

    static const size_t EP_OUT = 16;
    static const size_t EP_RECV = 17;

    static const size_t BUF_ADDR = 0x8000;
    static const size_t RECV_ADDR = 0x3F'FF00;
    static const size_t MAX_BUF_SIZE = 32768;

    enum Operation {
        COMPUTE,
        FORWARD,
        IDLE,
    };

    struct InvokeMsg {
        uint64_t op;
        uint64_t dataSize;
        uint64_t compTime;
    } PACKED;

    explicit InDirAccel(std::unique_ptr<ChildActivity> &act, RecvGate &reply_gate)
        : _mcap(),
          _act(act),
          _rep(EP::alloc_for(act->sel(), EP_RECV, 1)),
          _mep(EP::alloc_for(act->sel(), EP_OUT)),
          _rcap(create_rcap(act, _rep)),
          _sgate(SendGate::create(&_rcap, SendGateArgs().credits(1).reply_gate(&reply_gate))),
          _mem(_act->get_mem(_act->tile_desc().mem_offset(), act->tile_desc().mem_size(),
                             MemGate::RW)
                   .activate()) {
    }

    void connect_output(InDirAccel *accel) {
        _mcap = std::make_unique<MemCap>(accel->_mem.derive_cap(BUF_ADDR, MAX_BUF_SIZE));
        _mcap->activate_on(_mep);
    }

    void read(void *data, size_t size) {
        assert(size <= MAX_BUF_SIZE);
        _mem.read(data, size, BUF_ADDR);
    }

    void write(const void *data, size_t size) {
        assert(size <= MAX_BUF_SIZE);
        _mem.write(data, size, BUF_ADDR);
    }

    void start(Operation op, size_t dataSize, CycleDuration compTime, label_t reply_label) {
        MsgBuf msg_buf;
        auto &msg = msg_buf.cast<InvokeMsg>();
        msg.op = op;
        msg.dataSize = dataSize;
        msg.compTime = compTime.as_raw();
        _sgate.send(msg_buf, reply_label);
    }

private:
    static RecvCap create_rcap(std::unique_ptr<ChildActivity> &act, EP &rep) {
        auto rgate = RecvCap::create(getnextlog2(MSG_SIZE), getnextlog2(MSG_SIZE));
        // activate EP
        rgate.activate_on(rep, nullptr, act->tile_desc().mem_offset() + RECV_ADDR);
        return rgate;
    }

    std::unique_ptr<MemCap> _mcap;
    std::unique_ptr<ChildActivity> &_act;
    EP _rep;
    EP _mep;
    RecvCap _rcap;
    SendGate _sgate;
    MemGate _mem;
};

}
