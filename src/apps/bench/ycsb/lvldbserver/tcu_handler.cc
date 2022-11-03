/*
 * Copyright (C) 2022 Nils Asmussen, Barkhausen Institut
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

#include <m3/com/Semaphore.h>
#include <m3/stream/Standard.h>

#include <endian.h>

#include "handler.h"
#include "m3/com/GateStream.h"

using namespace m3;

static char result_buffer[1024];

TCUOpHandler::TCUOpHandler()
    : _rgate(RecvGate::create_named("req")),
      _result(MemGate::create_global(MAX_RESULT_SIZE, MemGate::W)),
      _last_req() {
    _rgate.activate();
}

OpHandler::Result TCUOpHandler::receive(Package &pkg, CycleInstant &start) {
    auto req = receive_msg(_rgate);
    start = CycleInstant::now();
    _last_req = new GateIStream(std::move(req));

    // There is an edge case where the package size is 6, If thats the case, check if we got the
    // end flag from the client. In that case its time to stop the benchmark.
    if(memcmp(_last_req->message().data, "ENDNOW", 6) == 0) {
        reply_vmsg(*_last_req, 0);
        delete _last_req;
        return Result::STOP;
    }

    UNUSED auto res = from_bytes(_last_req->message().data, _last_req->message().length, pkg);
    assert(res != Result::INCOMPLETE);

    return Result::READY;
}

bool TCUOpHandler::respond(CycleDuration total, CycleDuration xfer, size_t bytes) {
    size_t total_bytes = 0;
    while(total_bytes < bytes) {
        size_t amount = Math::min(total_bytes - bytes, sizeof(result_buffer));
        _result.write(result_buffer, amount, total_bytes);
        total_bytes += amount;
    }

    reply_vmsg(*_last_req, total.as_raw(), xfer.as_raw(), bytes);
    delete _last_req;

    return true;
}

Option<size_t> TCUOpHandler::send(const void *, size_t) {
    // unused
    return None;
}
