/*
 * Copyright (C) 2021 Nils Asmussen, Barkhausen Institut
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

#include <m3/net/Socket.h>
#include <m3/net/UdpSocket.h>
#include <m3/session/Network.h>

namespace m3 {

/**
 * Represents a raw IP socket
 */
class RawSocket : public Socket {
    friend class Socket;

    explicit RawSocket(int sd, capsel_t caps, Network &net);

public:
    /**
     * Creates a new raw IP sockets with given arguments.
     *
     * By default, the socket is in blocking mode, that is, all functions (send_to, recv_from, ...)
     * do not return until the operation is complete. This can be changed via set_blocking.
     *
     * Creation of a raw socket requires that the used session has permission to do so. This is
     * controlled with the "raw=yes" argument in the session argument of M³'s config files.
     *
     * @param net the network service
     * @param protocol the IP protocol
     * @param args optionally additional arguments that define the buffer sizes
     */
    static FileRef<RawSocket> create(Network &net, uint8_t protocol,
                                     const DgramSocketArgs &args = DgramSocketArgs());

    ~RawSocket();

    /**
     * Connect is not supported for raw sockets and therefore throws an exception.
     */
    virtual bool connect(const Endpoint &) override {
        throw Exception(Errors::NOT_SUP);
    }

    /**
     * Sends <amount> bytes from <src> over this socket.
     *
     * @param src the data to send
     * @param amount the number of bytes to send
     * @return the number of sent bytes (None if it would block and the socket is non-blocking)
     */
    virtual Option<size_t> send(const void *src, size_t amount) override;

    /**
     * Receives <amount> or a smaller number of bytes into <dst>.
     *
     * @param dst the destination buffer
     * @param amount the number of bytes to receive
     * @return the number of received bytes (None if it would block and the socket is non-blocking)
     */
    virtual Option<size_t> recv(void *dst, size_t amount) override;

private:
    void remove() noexcept override;
};

}
