/*
 * Copyright (C) 2015-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019-2021 Nils Asmussen, Barkhausen Institut
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

#include <base/util/Random.h>

#include <m3/com/GateStream.h>
#include <m3/com/SendQueue.h>
#include <m3/server/Server.h>
#include <m3/server/EventHandler.h>
#include <m3/session/arch/host/Keyboard.h>
#include <m3/session/ClientSession.h>
#include <m3/session/Timer.h>

using namespace m3;

static Server<EventHandler<>> *server;
static Random rng;

static void timer_irq(GateIStream &) {
    for(auto &h : server->handler()->sessions()) {
        // skip clients that have a session but no gate yet
        if(h.gate()) {
            MsgBuf msg;
            msg.cast<uint64_t>() = static_cast<uint64_t>(rng.get());
            SendQueue::get().send(*h.gate(), msg);
        }
    }
}

int main() {
    WorkLoop wl;

    Timer timer("timer");
    timer.rgate().start(&wl, timer_irq);

    // now, register service
    server = new Server<EventHandler<>>("queuetest", &wl, std::make_unique<EventHandler<>>());

    wl.add(&SendQueue::get(), true);
    wl.run();

    delete server;
    return 0;
}
