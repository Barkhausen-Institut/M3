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

#include <base/stream/IStringStream.h>
#include <base/tracing/Tracing.h>
#include <base/log/Kernel.h>

#include "mem/MainMemory.h"
#include "pes/PEManager.h"
#include "pes/VPEManager.h"
#include "Args.h"
#include "SyscallHandler.h"
#include "WorkLoop.h"

using namespace kernel;

int main(int argc, char *argv[]) {
    Args::parse(argc, argv);

    EVENT_TRACE_INIT_KERNEL();

    KLOG(MEM, MainMemory::get());

    WorkLoop &wl = WorkLoop::get();

    // create some worker threads
    wl.multithreaded(48);

    SyscallHandler::init();
    PEManager::create();
    VPEManager::create();
    VPEManager::get().start_root();

    PEManager::get().init();

    KLOG(INFO, "Kernel is ready");

    wl.run();

    EVENT_TRACE_FLUSH();

    KLOG(INFO, "Shutting down");

    VPEManager::destroy();

    size_t blocked = m3::ThreadManager::get().blocked_count();
    if(blocked > 0)
        KLOG(ERR, "\e[37;41m" << blocked << " blocked threads left\e[0m");

    m3::Machine::shutdown();
}
