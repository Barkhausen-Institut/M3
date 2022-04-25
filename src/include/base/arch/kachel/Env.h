/*
 * Copyright (C) 2016-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#pragma once

#include <base/Common.h>
#include <base/Config.h>
#include <base/EnvBackend.h>
#include <base/TileDesc.h>

namespace m3 {

class OStream;

class Env;
OStream &operator<<(OStream &, const Env &senv);

enum Platform {
    GEM5,
    HW
};

class Gem5EnvBackend : public EnvBackend {
    friend class Env;

public:
    virtual void init() = 0;
};

struct BootEnv {
    uint64_t platform;
    uint64_t tile_id;
    uint64_t tile_desc;
    uint64_t argc;
    uint64_t argv;
    uint64_t heap_size;
    uint64_t kenv;
    uint64_t lambda;
} PACKED;

class Env : public BootEnv {
    friend OStream &operator<<(OStream &, const Env &senv);

public:
    // set by TileMux
    uint64_t shared;

    uint64_t envp;
    uint64_t sp;
    uint64_t entry;
    uint64_t first_std_ep;
    uint64_t first_sel;
    uint64_t act_id;

    uint64_t rmng_sel;
    uint64_t pager_sess;
    uint64_t pager_sgate;

    uint64_t mounts_addr;
    uint64_t mounts_len;

    uint64_t fds_addr;
    uint64_t fds_len;

    uint64_t data_addr;
    uint64_t data_len;

    Gem5EnvBackend *backend() {
        return _backend;
    }
    void set_backend(Gem5EnvBackend *backend) {
        _backend = backend;
    }

    static void init() asm("env_init");
    static void run() asm("env_run");

    void exit(int code, bool abort) NORETURN;

private:
    void call_constr();

    Gem5EnvBackend *_backend;
} PACKED;

#define ENV_SPACE_SIZE           (ENV_SIZE - (sizeof(word_t) * 2 + sizeof(m3::Env)))
#define ENV_SPACE_START          (ENV_START + sizeof(m3::Env))
#define ENV_SPACE_END            (ENV_SPACE_START + ENV_SPACE_SIZE)

static inline Env *env() {
    return reinterpret_cast<Env*>(ENV_START);
}

}
