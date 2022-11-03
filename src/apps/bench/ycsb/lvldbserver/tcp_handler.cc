/*
 * Copyright (C) 2021 Nils Asmussen, Barkhausen Institut
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

using namespace m3;

static uint8_t package_buffer[8 * 1024];

TCPOpHandler::TCPOpHandler(NetworkManager &nm, m3::port_t port)
    : _socket(TcpSocket::create(
          nm, StreamSocketArgs().send_buffer(64 * 1024).recv_buffer(256 * 1024))) {
    _socket->listen(port);

    Semaphore::attach("net").up();

    Endpoint rem_ep;
    _socket->accept(&rem_ep);
    println("Accepted connection from {}"_cf, rem_ep);
}

OpHandler::Result TCPOpHandler::receive(Package &pkg, CycleInstant &start) {
    // First receive package size header
    union {
        uint32_t header_word;
        uint8_t header_bytes[4];
    };
    for(size_t i = 0; i < sizeof(header_bytes);)
        i += receive(header_bytes + i, sizeof(header_bytes) - i).unwrap();

    uint32_t package_size = be32toh(header_word);
    if(package_size > sizeof(package_buffer)) {
        eprintln("Invalid package header length {}"_cf, package_size);
        return Result::STOP;
    }

    // Receive the next package from the socket
    for(size_t i = 0; i < package_size;)
        i += receive(package_buffer + i, package_size - i).unwrap();

    start = CycleInstant::now();

    // There is an edge case where the package size is 6, If thats the case, check if we got the
    // end flag from the client. In that case its time to stop the benchmark.
    if(package_size == 6 && memcmp(package_buffer, "ENDNOW", 6) == 0)
        return Result::STOP;

    if(from_bytes(package_buffer, package_size, pkg) == 0)
        return Result::INCOMPLETE;
    return Result::READY;
}

Option<size_t> TCPOpHandler::receive(void *data, size_t max) {
    __m3_sysc_trace_start(SYSC_RECEIVE);
    auto res = _socket->recv(data, max);
    __m3_sysc_trace_stop();
    return res;
}

Option<size_t> TCPOpHandler::send(const void *data, size_t len) {
    __m3_sysc_trace_start(SYSC_SEND);
    auto res = _socket->send(data, len);
    __m3_sysc_trace_stop();
    return res;
}
