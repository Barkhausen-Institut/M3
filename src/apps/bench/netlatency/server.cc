/*
 * Copyright (C) 2017, Georg Kotheimer <georg.kotheimer@mailbox.tu-dresden.de>
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

#include <base/util/Profile.h>
#include <base/Env.h>

#include <m3/session/NetworkManager.h>
#include <m3/stream/Standard.h>

using namespace m3;

int main() {
    NetworkManager net("net1");
    String status;

    Socket * socket = net.create(Socket::SOCK_DGRAM);
    if(!socket)
        exitmsg("Socket creation failed");
    socket->blocking(true);

    Errors::Code err = socket->bind(IpAddr(192, 168, 112, 1), 1337);
    if(err != Errors::NONE)
        exitmsg("Socket bind failed: " << Errors::to_string(err));

    socket->listen();

    char request[1024];
    while(true) {
        IpAddr addr;
        uint16_t port;
        ssize_t len = socket->recvmsg(request, sizeof(request), &addr, &port);

        len = socket->sendto(request, static_cast<size_t>(len), addr, port);
    }
}
