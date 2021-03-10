/*
 * Copyright (C) 2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Copyright (C) 2021, Tendsin Mende <tendsin.mende@mailbox.tu-dresden.de>
 * Copyright (C) 2018, Georg Kotheimer <georg.kotheimer@mailbox.tu-dresden.de>
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

#include <m3/Exception.h>
#include <m3/netrs/Socket.h>
#include <m3/netrs/TcpSocket.h>
#include <m3/session/NetworkManagerRs.h>

namespace m3 {

TcpSocketRs::TcpSocketRs(int sd, NetworkManagerRs &nm)
    : SocketRs(sd, nm) {
}

TcpSocketRs::~TcpSocketRs() {
    try {
        abort();
    }
    catch(...) {
        // ignore errors here
    }

    // Clear receive queue before potentially destroying the channel,
    // because the queue contains events that point to the channel.
    _recv_queue.clear();

    _nm.remove_socket(this);
}

Reference<TcpSocketRs> TcpSocketRs::create(NetworkManagerRs &nm) {
    int sd = nm.create(SOCK_STREAM, 0);
    auto sock = new TcpSocketRs(sd, nm);
    nm.add_socket(sock);
    return Reference<TcpSocketRs>(sock);
}

void TcpSocketRs::close() {
    bool sent_req = false;

    while(_state != State::Closed) {
        if(!sent_req) {
            if(_nm.close(sd()))
                sent_req = true;
        }

        if(!_blocking)
            throw Exception(Errors::IN_PROGRESS);

        _nm.wait_sync();

        process_events();
    }
}

void TcpSocketRs::listen(IpAddr local_addr, uint16_t local_port) {
    if(_state != State::Closed)
        inv_state();

    _nm.listen(sd(), local_addr, local_port);
    set_local(local_addr, local_port, State::Listening);
}

void TcpSocketRs::connect(IpAddr remote_addr, uint16_t remote_port, uint16_t local_port) {
    if(_state == State::Connected) {
        if(!(_remote_addr == remote_addr && _remote_port == remote_port &&
             _local_port == local_port)) {
            throw Exception(Errors::IS_CONNECTED);
        }
        return;
    }

    if(_state == State::Connecting)
        throw Exception(Errors::ALREADY_IN_PROGRESS);

    _nm.connect(sd(), remote_addr, remote_port, local_port);
    _state = State::Connecting;
    _remote_addr = remote_addr;
    _remote_port = remote_port;
    _local_port = local_port;

    if(!_blocking)
        throw Exception(Errors::IN_PROGRESS);

    while(_state == State::Connecting) {
        wait_for_event();
        process_events();
    }

    if(_state != Connected)
        inv_state();
}

void TcpSocketRs::accept(IpAddr *remote_addr, uint16_t *remote_port) {
    if(_state == State::Connected) {
        *remote_addr = _remote_addr;
        *remote_port = _remote_port;
        return;
    }
    if(_state == State::Connecting)
        throw Exception(Errors::ALREADY_IN_PROGRESS);
    if(_state != State::Listening)
        inv_state();

    _state = State::Connecting;
    while(_state == State::Connecting) {
        wait_for_event();
        process_events();
    }

    if(_state != State::Connected)
        inv_state();
}

ssize_t TcpSocketRs::recvfrom(void *dst, size_t amount, IpAddr *src_addr, uint16_t *src_port) {
    // Allow receiving that arrived before the socket/connection was closed.
    if(_state != Connected && _state != Closed)
        throw Exception(Errors::NOT_CONNECTED);

    return SocketRs::recvfrom(dst, amount, src_addr, src_port);
}

ssize_t TcpSocketRs::sendto(const void *src, size_t amount, IpAddr dst_addr, uint16_t dst_port) {
    if(_state != Connected)
        throw Exception(Errors::NOT_CONNECTED);

    return SocketRs::sendto(src, amount, dst_addr, dst_port);
}

}
