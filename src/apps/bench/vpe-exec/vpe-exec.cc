/*
 * Copyright (C) 2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <base/Common.h>
#include <base/stream/Serial.h>
#include <base/stream/OStringStream.h>
#include <base/util/Time.h>

#include <m3/com/MemGate.h>
#include <m3/stream/Standard.h>
#include <m3/vfs/File.h>
#include <m3/vfs/VFS.h>
#include <m3/pes/VPE.h>

using namespace m3;

static constexpr int REPEATS = 20;

int main(int argc, char **argv) {
    if(argc < 2)
        exitmsg("Usage: " << argv[0] << " <size>");

    OStringStream os;
    os << "/bin/bench-vpe-clone-" << argv[1];

    auto pe = PE::get("core|own");
    for(int i = 0; i < REPEATS; ++i) {
        Time::start(1);

        VPE vpe(pe, "hello");
        const char *args[] = {os.str(), "dummy"};
        vpe.exec(ARRAY_SIZE(args), args);

        vpe.wait();
    }

    cout << "Time for exec: 0 cycles\n";
    return 0;
}
