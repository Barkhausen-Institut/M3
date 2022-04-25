/*
 * Copyright (C) 2015-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019-2022 Nils Asmussen, Barkhausen Institut
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

#include <base/log/Lib.h>
#include <base/Backtrace.h>
#include <base/Env.h>
#include <base/TCU.h>
#include <base/Init.h>
#include <base/Panic.h>

#include <sys/mman.h>
#include <fstream>
#include <unistd.h>
#include <fcntl.h>

#ifndef NDEBUG
volatile int wait_for_debugger = 1;
#endif

namespace m3 {

void *Env::_mem = nullptr;
Env *Env::_inst = nullptr;
INIT_PRIO_ENV Env::Init Env::_init;
char Env::_exec[128];
char Env::_exec_short[128];
const char *Env::_exec_short_ptr = nullptr;

HostEnvBackend::HostEnvBackend() {
}

HostEnvBackend::~HostEnvBackend() {
}

Env::Init::Init() {
#ifndef NDEBUG
    char *val = getenv("M3_WAIT");
    if(val) {
        const char *exec = Env::executable();
        size_t vlen = strlen(val);
        size_t elen = strlen(exec);
        if(elen >= vlen && strcmp(exec + elen - vlen, val) == 0 &&
            (elen == vlen || exec[elen - vlen - 1] == '/')) {
            while(wait_for_debugger)
                usleep(20000);
        }
    }
#endif

    m3::Heap::init();
    Env::init();

    Serial::init(executable(), env()->tile_id);
}

Env::Init::~Init() {
}

const char *Env::tmp_dir() {
    return getenv("M3_HOST_TMP");
}

const char *Env::out_dir() {
    return getenv("M3_OUT");
}

Env::Env(EnvBackend *backend, int logfd)
    : tile_id(set_inst(this)),
      shared(false),
      first_std_ep(0),
      envp(),
      _backend(backend),
      _logfd(logfd),
      _shm_prefix(),
      _sysc_label(),
      _sysc_epid(),
      _sysc_credits(),
      _log_mutex(PTHREAD_MUTEX_INITIALIZER) {
}

void Env::init_executable() {
    int fd = open("/proc/self/cmdline", O_RDONLY);
    if(fd == -1)
        PANIC("open");
    if(read(fd, _exec, sizeof(_exec)) == -1)
        PANIC("read");
    close(fd);
    strncpy(_exec_short, _exec, sizeof(_exec_short));
    _exec_short[sizeof(_exec_short) - 1] = '\0';
    _exec_short_ptr = basename(_exec_short);
}

void *Env::mem() {
    if(_mem == nullptr) {
        _mem = mmap(0, LOCAL_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if(_mem == MAP_FAILED)
            PANIC("Unable to map heap");
    }
    return _mem;
}

void Env::print() const {
    char **env = environ;
    while(*env) {
        if(strstr(*env, "M3_") != nullptr || strstr(*env, "LD_") != nullptr) {
            char *dup = strdup(*env);
            char *name = strtok(dup, "=");
            printf("%s = %s\n", name, getenv(name));
            free(dup);
        }
        env++;
    }
}

Env::~Env() {
    delete _backend;
}

}
