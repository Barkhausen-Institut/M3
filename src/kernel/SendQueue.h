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

#pragma once

#include <base/Common.h>
#include <base/col/SList.h>
#include <base/DTU.h>

namespace kernel {

struct Timeout;
class VPE;

class SendQueue {
    struct Entry : public m3::SListItem {
        explicit Entry(uint64_t _id, epid_t _dst_ep, label_t _ident, const void *_msg, size_t _size)
            : SListItem(),
              id(_id),
              dst_ep(_dst_ep),
              ident(_ident),
              msg(_msg),
              size(_size) {
        }

        uint64_t id;
        epid_t dst_ep;
        label_t ident;
        const void *msg;
        size_t size;
    };

public:
    explicit SendQueue(VPE &vpe)
        : _vpe(vpe),
          _queue(),
          _cur_event(),
          _inflight(0),
          _timeout() {
    }
    ~SendQueue();

    VPE &vpe() const {
        return _vpe;
    }
    int inflight() const {
        return _inflight;
    }
    int pending() const {
        return static_cast<int>(_queue.length());
    }

    event_t send(epid_t dst_ep, label_t ident,const void *msg, size_t size, bool onheap);
    void received_reply(epid_t ep, const m3::DTU::Message *msg);
    void drop_msgs(label_t ident);
    void abort();

private:
    void send_pending();
    event_t get_event(uint64_t id);
    event_t do_send(epid_t dst_ep, uint64_t id, const void *msg, size_t size, bool onheap);

    VPE &_vpe;
    m3::SList<Entry> _queue;
    event_t _cur_event;
    int _inflight;
    Timeout *_timeout;
    static uint64_t _next_id;
};

}
