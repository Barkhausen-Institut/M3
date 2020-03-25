/*
 * Copyright (C) 2016-2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <base/stream/Serial.h>
#include <base/CmdArgs.h>
#include <base/Config.h>
#include <base/Machine.h>

#include "Args.h"

namespace kernel {

size_t Args::kmem          = 64 * 1024 * 1024;
const char *Args::bridge   = nullptr;
const char *Args::fsimg    = nullptr;
bool Args::disk       = false;

void Args::usage(const char *name) {
    m3::Serial::get() << "Usage: " << name << " [-f <fsimg>] [-b <bridge>] [-m <kmem>] [-d] ...\n";
    m3::Serial::get() << "  -t: the timeslices for all VPEs\n";
    m3::Serial::get() << "  -b: the network bridge to create (only used on host)\n";
    m3::Serial::get() << "  -m: the kernel memory size (> FIXED_KMEM)\n";
    m3::Serial::get() << "  -d: enable disk device (host only)\n";
    m3::Machine::shutdown();
}

int Args::parse(int argc, char **argv) {
    int opt;
    while((opt = m3::CmdArgs::get(argc, argv, "f:t:b:m:d")) != -1) {
        switch(opt) {
            case 'f': fsimg = m3::CmdArgs::arg; break;
            case 'b': bridge = m3::CmdArgs::arg; break;
            case 'd': disk = true; break;
            case 'm':
                kmem = m3::CmdArgs::to_size(m3::CmdArgs::arg);
                if(kmem <= FIXED_KMEM)
                    usage(argv[0]);
                break;
            default: usage(argv[0]);
        }
    }

    return m3::CmdArgs::ind;
}

}
