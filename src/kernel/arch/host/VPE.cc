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

#include <base/log/Kernel.h>
#include <base/Panic.h>

#include <unistd.h>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <cerrno>

#include "pes/VPEManager.h"
#include "pes/VPE.h"
#include "SyscallHandler.h"

namespace kernel {

static void write_env_file(epid_t ep, pid_t pid, peid_t pe, label_t label) {
    char tmpfile[64];
    snprintf(tmpfile, sizeof(tmpfile), "/tmp/m3/%d", pid);
    std::ofstream of(tmpfile);
    of << m3::env()->shm_prefix().c_str() << "\n";
    of << pe << "\n";
    of << label << "\n";
    of << ep << "\n";
    of << (1 << VPE::SYSC_CREDIT_ORD) << "\n";
}

void VPE::init() {
    // update all EPs (e.g., to allow parents to activate EPs for their childs)
    for(epid_t ep = m3::DTU::FIRST_FREE_EP; ep < EP_COUNT; ++ep) {
        // set base for all receive EPs (for do it for all, but it's just unused for the other types)
        _dtustate.update_recv(ep, rbuf_base());
        update_ep(ep);
    }
}

void VPE::load_app() {
    if(_pid == 0) {
        _pid = fork();
        if(_pid < 0)
            PANIC("fork");
        if(_pid == 0) {
            write_env_file(syscall_ep(), getpid(), pe(), reinterpret_cast<label_t>(this));
            char **childargs = new char*[_argc + 1];
            size_t i = 0, j = 0;
            for(; i < _argc; ++i) {
                if(strncmp(_argv[i], "pe=", 5) == 0)
                    continue;
                else if(strcmp(_argv[i], "daemon") == 0)
                    continue;
                else if(strncmp(_argv[i], "requires=", sizeof("requires=") - 1) == 0)
                    continue;

                childargs[j++] = const_cast<char*>(_argv[i]);
            }
            childargs[j] = nullptr;
            execv(childargs[0], childargs);
            KLOG(VPES, "VPE creation failed: " << strerror(errno));
            // special error code to let the WorkLoop delete the VPE
            exit(255);
        }
    }
    else
        write_env_file(syscall_ep(), _pid, pe(), reinterpret_cast<label_t>(this));

    KLOG(VPES, "Started VPE '" << _name << "' [pid=" << _pid << "]");
}

void VPE::init_memory() {
    load_app();
}

}
