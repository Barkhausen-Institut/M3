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

#pragma once

#include <base/log/Log.h>

#define LLOG(lvl, msg)  LOG(LibLog, lvl, msg)

namespace m3 {

class LibLog {
    LibLog() = delete;

public:
    enum Level {
        DEF         = 1 << 0,
        TCU         = 1 << 1,
        TCUERR      = 1 << 2,
        IPC         = 1 << 3,
        TRACE       = 1 << 4,
        IRQS        = 1 << 5,
        SHM         = 1 << 6,
        HEAP        = 1 << 7,
        FS          = 1 << 8,
        SERV        = 1 << 9,
        THREAD      = 1 << 10,
        ACCEL       = 1 << 11,
        FILES       = 1 << 12,
        NET 		= 1 << 13,
        DIRPIPE     = 1 << 14,
    };

    static const int level = DEF | TCUERR;
};

}
