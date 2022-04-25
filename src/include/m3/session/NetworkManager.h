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

#pragma once

#include <m3/com/SendGate.h>
#include <m3/net/Net.h>
#include <m3/net/NetEventChannel.h>
#include <m3/net/Socket.h>
#include <m3/session/ClientSession.h>
#include <m3/vfs/GenericFile.h>

namespace m3 {

class UdpSocket;
class TcpSocket;
class RawSocket;
class DNS;

/**
 * Represents a session at the network service, allowing to create and use sockets
 *
 * To exchange events and data with the server, the NetEventChannel is used, which allows to send
 * and receive multiple messages. Events are used to receive connected or closed events from the
 * server and to send close requests to the server. Transmitted and received data is exchanged via
 * the NetEventChannel in both directions.
 */
class NetworkManager : public ClientSession {
    friend class Socket;
    friend class UdpSocket;
    friend class TcpSocket;
    friend class RawSocket;
    friend class DNS;

    enum Operation {
        STAT            = GenericFile::STAT,
        SEEK            = GenericFile::SEEK,
        NEXT_IN         = GenericFile::NEXT_IN,
        NEXT_OUT        = GenericFile::NEXT_OUT,
        COMMIT          = GenericFile::COMMIT,
        TRUNCATE        = GenericFile::TRUNCATE,
        CLOSE           = GenericFile::CLOSE,
        CLONE           = GenericFile::CLONE,
        SET_TMODE       = GenericFile::SET_TMODE,
        SET_DEST        = GenericFile::SET_DEST,
        ENABLE_NOTIFY   = GenericFile::ENABLE_NOTIFY,
        REQ_NOTIFY      = GenericFile::REQ_NOTIFY,
        BIND,
        LISTEN,
        CONNECT,
        ABORT,
        CREATE,
        GET_IP,
        GET_NAMESRV,
        GET_SGATE,
        OPEN_FILE,
    };

public:
    /**
     * Creates a new instance for `service`
     *
     * @param service the service name
     */
    explicit NetworkManager(const String &service);

    /**
     * @return the local IP address
     */
    IpAddr ip_addr();

private:
    static KIF::CapRngDesc get_sgate(ClientSession &sess);

    const SendGate &meta_gate() const noexcept {
        return _metagate;
    }

    int32_t create(SocketType type, uint8_t protocol, const SocketArgs &args, capsel_t *caps);
    IpAddr get_nameserver();
    IpAddr bind(int32_t sd, port_t *port);
    IpAddr listen(int32_t sd, port_t port);
    Endpoint connect(int32_t sd, Endpoint remote_ep);
    void abort(int32_t sd, bool remove);

    SendGate _metagate;
};

}
