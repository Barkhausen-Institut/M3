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

    static const size_t BUF_ADDR = MEM_OFFSET + 0x8000;
    static const size_t RECV_ADDR = MEM_OFFSET + 0x3F'FF00;
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
        : _mgate(),
          _rgate(RecvGate::create(getnextlog2(MSG_SIZE), getnextlog2(MSG_SIZE))),
          _sgate(SendGate::create(&_rgate, SendGateArgs().credits(1).reply_gate(&reply_gate))),
          _rep(EP::alloc_for(*act, EP_RECV, _rgate.slots())),
          _mep(EP::alloc_for(*act, EP_OUT)),
          _act(act),
          _mem(_act->get_mem(MEM_OFFSET, act->tile_desc().mem_size(), MemGate::RW)) {
        // activate EP
        _rgate.activate_on(_rep, nullptr, RECV_ADDR);
    }

    void connect_output(InDirAccel *accel) {
        _mgate = std::make_unique<MemGate>(accel->_mem.derive(BUF_ADDR - MEM_OFFSET, MAX_BUF_SIZE));
        _mgate->activate_on(_mep);
    }

    void read(void *data, size_t size) {
        assert(size <= MAX_BUF_SIZE);
        _mem.read(data, size, BUF_ADDR - MEM_OFFSET);
    }

    void write(const void *data, size_t size) {
        assert(size <= MAX_BUF_SIZE);
        _mem.write(data, size, BUF_ADDR - MEM_OFFSET);
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
    std::unique_ptr<MemGate> _mgate;
    RecvGate _rgate;
    SendGate _sgate;
    EP _rep;
    EP _mep;
    std::unique_ptr<ChildActivity> &_act;
    MemGate _mem;
};

}
