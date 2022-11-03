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

#include <base/stream/IStringStream.h>
#include <base/time/Profile.h>

#include <m3/Test.h>
#include <m3/session/NetworkManager.h>
#include <m3/stream/Standard.h>
#include <m3/vfs/VFS.h>

#include <iostream>
#include <sstream>
#include <string>

#include "handler.h"
#include "leveldb/db.h"
#include "leveldb/write_batch.h"
#include "ops.h"

using namespace m3;

int main(int argc, char **argv) {
    if(argc != 4 && argc != 5 && argc != 7) {
        eprintln("Usage: {} <db> <repeats> tcp <port>"_cf, argv[0]);
        eprintln("Usage: {} <db> <repeats> tcu"_cf, argv[0]);
        eprintln("Usage: {} <db> <repeats> udp <ip> <port> <workload>"_cf, argv[0]);
        return 1;
    }

    NetworkManager *net = nullptr;

    VFS::mount("/", "m3fs", "m3fs");

    const char *file = argv[1];
    int repeats = IStringStream::read_from<int>(argv[2]);

    Executor *exec = Executor::create(file);

    OpHandler *hdl;
    if(strcmp(argv[3], "tcp") == 0) {
        port_t port = IStringStream::read_from<port_t>(argv[4]);
        net = new NetworkManager("net");
        hdl = new TCPOpHandler(*net, port);
    }
    else if(strcmp(argv[3], "udp") == 0) {
        IpAddr ip = IStringStream::read_from<IpAddr>(argv[4]);
        port_t port = IStringStream::read_from<port_t>(argv[5]);
        const char *workload = argv[6];
        net = new NetworkManager("net");
        hdl = new UDPOpHandler(*net, workload, ip, port);
    }
    else
        hdl = new TCUOpHandler();

    println("Starting Benchmark:"_cf);

    Results<TimeDuration> res(static_cast<size_t>(repeats));
    for(int i = 0; i < repeats; ++i) {
        uint64_t opcounter = 0;

        __m3_sysc_trace(true, 32768);
        exec->reset_stats();
        hdl->reset();

        auto start = TimeInstant::now();

        bool run = true;
        while(run) {
            auto old_xfer_time = GenericFile::xfer_time;
            CycleInstant op_start = CycleInstant::from_cycles(0);

            Package pkg;
            switch(hdl->receive(pkg, op_start)) {
                case OpHandler::STOP: run = false; continue;
                case OpHandler::INCOMPLETE: continue;
                case OpHandler::READY: break;
            }

            if((opcounter % 100) == 0)
                println("Op={} @ {}"_cf, pkg.op, opcounter);

            size_t res_bytes = exec->execute(pkg);

            auto op_end = CycleInstant::now();

            if(!hdl->respond(op_end.duration_since(op_start),
                             GenericFile::xfer_time - old_xfer_time, res_bytes))
                break;

            opcounter += 1;
        }

        auto end = TimeInstant::now();
        println("Systemtime: {} us"_cf, __m3_sysc_systime() / 1000);
        println("Totaltime: {} us"_cf, end.duration_since(start).as_micros());

        println("Server Side:"_cf);
        exec->print_stats(opcounter);
        res.push(end.duration_since(start));
    }

    auto name = OStringStream();
    format_to(name, "YCSB with {}"_cf, argv[3]);
    WVPERF(name.str(), res);

    delete hdl;
    delete net;

    return 0;
}
