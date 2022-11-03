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
#include <m3/vfs/VFS.h>

#include <endian.h>

#include "handler.h"

using namespace m3;

constexpr size_t MAX_FILE_SIZE = 4 * 1024 * 1024;

static uint8_t *wl_buffer;
static size_t wl_pos;
static size_t wl_size;

static uint32_t wl_read4b() {
    union {
        uint32_t word;
        uint8_t bytes[4];
    };
    memcpy(bytes, wl_buffer + wl_pos, sizeof(bytes));
    wl_pos += 4;
    return be32toh(word);
}

UDPOpHandler::UDPOpHandler(NetworkManager &nm, const char *workload, m3::IpAddr ip, m3::port_t port)
    : _ops(),
      _total_ops(),
      _ep(ip, port),
      _socket(UdpSocket::create(
          nm, DgramSocketArgs().send_buffer(4, 16 * 1024).recv_buffer(64, 512 * 1024))) {
    wl_buffer = new uint8_t[MAX_FILE_SIZE];
    wl_pos = 0;
    wl_size = 0;
    {
        auto wl_file = VFS::open(workload, FILE_R);
        size_t len;
        while((len = wl_file->read(wl_buffer + wl_size, MAX_FILE_SIZE - wl_size).unwrap()) > 0)
            wl_size += len;
    }

    UNUSED uint64_t total_preins = static_cast<uint64_t>(wl_read4b());
    _total_ops = static_cast<uint64_t>(wl_read4b());
}

void UDPOpHandler::reset() {
    wl_pos = 4 * 2;
    _ops = 0;
}

OpHandler::Result UDPOpHandler::receive(Package &pkg, CycleInstant &start) {
    if(_ops >= _total_ops)
        return Result::STOP;

    start = CycleInstant::now();

    size_t read_size = from_bytes(wl_buffer + wl_pos, wl_size - wl_pos, pkg);
    wl_pos += read_size;

    send(wl_buffer, read_size);

    _ops++;
    return Result::READY;
}

Option<size_t> UDPOpHandler::send(const void *data, size_t len) {
    __m3_sysc_trace_start(SYSC_SEND);
    auto res = _socket->send_to(data, len, _ep);
    __m3_sysc_trace_stop();
    return res;
}
