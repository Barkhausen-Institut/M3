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

#include <base/Common.h>
#include <base/stream/Serial.h>
#include <base/CPU.h>
#include <base/Env.h>

#include <exception>
#include <functional>
#include <stdlib.h>

typedef void (*constr_func)();

extern constr_func CTORS_BEGIN;
extern constr_func CTORS_END;

EXTERN_C void __m3_init_libc(int argc, char **argv, char **envp);
EXTERN_C void __cxa_finalize(void *);
EXTERN_C void _init();
EXTERN_C int main(int argc, char **argv);

namespace m3 {

OStream &operator<<(OStream &os, const Env &senv) {
    os << "tile_id        : " << senv.tile_id << "\n";
    os << "tile_desc      : " << fmt(senv.tile_desc, "#x") << "\n";
    os << "argc         : " << senv.argc << "\n";
    os << "argv         : " << fmt(senv.argv, "p") << "\n";
    os << "heap_size    : " << fmt(senv.heap_size, "#x") << "\n";
    os << "sp           : " << fmt(senv.sp, "p") << "\n";
    os << "entry        : " << fmt(senv.entry, "p") << "\n";
    os << "shared       : " << senv.shared << "\n";
    os << "first_std_ep : " << senv.first_std_ep << "\n";
    os << "first_sel    : " << senv.first_sel << "\n";
    os << "act_id       : " << senv.act_id << "\n";
    os << "lambda       : " << fmt(senv.lambda, "p") << "\n";
    os << "rmng_sel     : " << senv.rmng_sel << "\n";
    os << "pager_sess   : " << senv.pager_sess << "\n";
    os << "mounts_addr  : " << fmt(senv.mounts_addr, "p") << "\n";
    os << "mounts_len   : " << senv.mounts_len << "\n";
    os << "fds_addr     : " << senv.fds_addr << "\n";
    os << "fds_len      : " << fmt(senv.fds_len, "p") << "\n";
    os << "data_addr    : " << senv.data_addr << "\n";
    os << "data_len     : " << fmt(senv.data_len, "p") << "\n";
    return os;
}

void Env::call_constr() {
    _init();
    for(constr_func *func = &CTORS_BEGIN; func < &CTORS_END; ++func)
        (*func)();
}

static char **rewrite_args(uint64_t *args, int count) {
    char **nargs = new char*[count + 1];
    for(int i = 0; i < count; ++i)
        nargs[i] = reinterpret_cast<char*>(args[i]);
    nargs[count] = nullptr;
    return nargs;
}

void Env::run() {
    Env *e = env();

    // ensure that the heap is initialized before potentially cloning argv below
    m3::Heap::init();

    int argc = static_cast<int>(e->argc);
    char **argv = reinterpret_cast<char**>(e->argv);
    char **envp = reinterpret_cast<char**>(e->envp);
    if(sizeof(char*) != sizeof(uint64_t)) {
        uint64_t *envp64 = reinterpret_cast<uint64_t*>(e->envp);
        int envcnt = 0;
        for(; envp64 && *envp64; envcnt++)
            envp64++;
        envp = rewrite_args(reinterpret_cast<uint64_t*>(e->envp), envcnt);
        argv = rewrite_args(reinterpret_cast<uint64_t*>(e->argv), argc);
    }

    __m3_init_libc(argc, argv, envp);
    Env::init();

    int res;
    if(e->lambda) {
        auto func = reinterpret_cast<int(*)()>(e->lambda);
        res = (*func)();
    }
    else
        res = main(argc, argv);

    ::exit(res);
    UNREACHED;
}

USED void Env::exit(int code, bool abort) {
    if(!abort)
        __cxa_finalize(nullptr);
    backend()->exit(code);
    UNREACHED;
}

}
