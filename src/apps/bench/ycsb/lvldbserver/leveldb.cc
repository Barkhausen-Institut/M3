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
#include <m3/com/MemGate.h>
#include <m3/session/Network.h>
#include <m3/stream/Standard.h>
#include <m3/vfs/VFS.h>

#include <iostream>
#include <sstream>
#include <string>
#include <unistd.h>

#include "handler.h"
#include "leveldb/db.h"
#include "leveldb/write_batch.h"
#include "ops.h"

using namespace m3;

void usage(const char *prog) {
    eprintln("Usage: {} [-s <shmem>] [-r <repeats>] [-w <warmup>] <db> <mode> [...]"_cf, prog);
    eprintln("  The following modes are supported:"_cf);
    eprintln("    tcp <port>"_cf);
    eprintln("    tcu"_cf);
    eprintln("    udp <ip> <port> <workload>"_cf);
    exit(1);
}

int main(int argc, char **argv) {
    const char *shmem_name = nullptr;
    int repeats = 4;
    int warmup = 1;

    int opt;
    while((opt = getopt(argc, argv, "s:r:w:")) != -1) {
        switch(opt) {
            case 's': shmem_name = optarg; break;
            case 'r': repeats = IStringStream::read_from<int>(optarg); break;
            case 'w': warmup = IStringStream::read_from<int>(optarg); break;
            default: usage(argv[0]);
        }
    }

    int remaining = argc - optind;
    if(remaining < 3)
        usage(argv[0]);

    Network *net = nullptr;

    // give ourself access to the shared memory area of the file system
    MemCap *shmem = nullptr;
    Reference<Tile> shmemtile;
    if(shmem_name != nullptr) {
        shmem = new MemCap(MemCap::attach_shmem(shmem_name));
        shmemtile = Tile::from_shmem(shmem_name);
        shmem->make_exclusive(shmemtile, Activity::own().tile(), false);
    }

    VFS::mount("/", "m3fs", "m3fs");

    // ensure that /tmp exists (necessary if the FS is empty)
    FileInfo info;
    if(VFS::try_stat("/tmp", info) != Errors::SUCCESS)
        VFS::mkdir("/tmp", 0755);

    const char *db = argv[optind + 0];
    std::string mode = argv[optind + 1];

    Executor *exec = Executor::create(db);

    println("Creating handler {}..."_cf, mode);

    OpHandler *hdl;
    if(mode == "tcp") {
        port_t port = IStringStream::read_from<port_t>(argv[optind + 2]);
        net = new Network("net");
        hdl = new TCPOpHandler(*net, port);
    }
    else if(mode == "udp") {
        IpAddr ip = IStringStream::read_from<IpAddr>(argv[optind + 2]);
        port_t port = IStringStream::read_from<port_t>(argv[optind + 3]);
        const char *workload = argv[optind + 4];
        net = new Network("net");
        hdl = new UDPOpHandler(*net, workload, ip, port);
    }
    else if(mode == "tcu")
        hdl = new TCUOpHandler();
    else
        usage(argv[0]);

    println("Starting Benchmark:"_cf);

    Results<TimeDuration> res(static_cast<size_t>(repeats));
    for(int i = 0; i < warmup + repeats; ++i) {
        uint64_t opcounter = 0;

        __m3_sysc_trace(true, 32768);
        exec->reset();
        hdl->reset();

        auto start = TimeInstant::now();

        bool run = true;
        while(run) {
            Package pkg;
            switch(hdl->receive(pkg)) {
                case OpHandler::STOP: run = false; continue;
                case OpHandler::INCOMPLETE: continue;
                case OpHandler::READY: break;
            }

            if((opcounter % 100) == 0)
                println("Op={} @ {}"_cf, pkg.op, opcounter);

            size_t res_bytes = exec->execute(pkg);

            if(!hdl->respond(res_bytes))
                break;

            opcounter += 1;
        }

        auto end = TimeInstant::now();
        println("Systemtime: {} us"_cf, __m3_sysc_systime() / 1000);
        println("Totaltime: {} us"_cf, end.duration_since(start).as_micros());

        println("Server Side:"_cf);
        exec->print_stats(opcounter);
        if(i >= warmup)
            res.push(end.duration_since(start));
    }

    auto name = OStringStream();
    format_to(name, "YCSB with {}"_cf, mode);
    WVPERF(name.str(), res);

    delete hdl;
    delete net;

    return 0;
}
