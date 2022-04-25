/*
 * Copyright (C) 2021-2022 Nils Asmussen, Barkhausen Institut
 * Copyright (C) 2021, Tendsin Mende <tendsin.mende@mailbox.tu-dresden.de>
 * Copyright (C) 2017, Georg Kotheimer <georg.kotheimer@mailbox.tu-dresden.de>
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

#include <base/log/Lib.h>
#include <base/time/Instant.h>

#include <m3/Exception.h>
#include <m3/com/GateStream.h>
#include <m3/net/Socket.h>
#include <m3/session/NetworkManager.h>
#include <m3/stream/Standard.h>

#include <thread/ThreadManager.h>

namespace m3 {

KIF::CapRngDesc NetworkManager::get_sgate(ClientSession &sess) {
    KIF::ExchangeArgs eargs;
    ExchangeOStream os(eargs);
    os << Operation::GET_SGATE;
    eargs.bytes = os.total();
    return sess.obtain(1, &eargs);
}

NetworkManager::NetworkManager(const String &service)
    : ClientSession(service),
      _metagate(SendGate::bind(get_sgate(*this).start())) {
}

int32_t NetworkManager::create(SocketType type, uint8_t protocol, const SocketArgs &args,
                               capsel_t *caps) {
    KIF::ExchangeArgs eargs;
    ExchangeOStream os(eargs);
    os << Operation::CREATE
       << static_cast<uint64_t>(type) << protocol
       << args.rbuf_size << args.rbuf_slots
       << args.sbuf_size << args.sbuf_slots;
    eargs.bytes = os.total();
    KIF::CapRngDesc crd = obtain(2, &eargs);
    *caps = crd.start();

    int32_t sd;
    ExchangeIStream is(eargs);
    is >> sd;
    return sd;
}

IpAddr NetworkManager::ip_addr() {
    GateIStream reply = send_receive_vmsg(_metagate, GET_IP);
    reply.pull_result();
    uint32_t addr;
    reply >> addr;
    return IpAddr(addr);
}

IpAddr NetworkManager::get_nameserver() {
    GateIStream reply = send_receive_vmsg(_metagate, GET_NAMESRV);
    reply.pull_result();
    uint32_t addr;
    reply >> addr;
    return IpAddr(addr);
}

IpAddr NetworkManager::bind(int32_t sd, port_t *port) {
    GateIStream reply = send_receive_vmsg(_metagate, BIND, sd, *port);
    reply.pull_result();
    uint32_t addr;
    reply >> addr >> *port;
    return IpAddr(addr);
}

IpAddr NetworkManager::listen(int32_t sd, port_t port) {
    GateIStream reply = send_receive_vmsg(_metagate, LISTEN, sd, port);
    reply.pull_result();
    uint32_t addr;
    reply >> addr;
    return IpAddr(addr);
}

Endpoint NetworkManager::connect(int32_t sd, Endpoint remote_ep) {
    GateIStream reply = send_receive_vmsg(_metagate, CONNECT, sd,
                                          remote_ep.addr.addr(), remote_ep.port);
    reply.pull_result();
    uint32_t addr;
    port_t port;
    reply >> addr >> port;
    return Endpoint(IpAddr(addr), port);
}

void NetworkManager::abort(int32_t sd, bool remove) {
    GateIStream reply = send_receive_vmsg(_metagate, ABORT, sd, remove);
    reply.pull_result();
}

} // namespace m3
