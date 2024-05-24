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

#if defined(__m3lx__)
#    include <base/arch/linux/Init.h>
#endif
#include <base/Common.h>
#include <base/Config.h>
#include <base/Errors.h>

namespace m3 {

enum Platform {
    GEM5,
    HW
};

struct BootEnv {
    uint64_t platform;
    uint64_t tile_id;
    uint64_t tile_desc;
    uint64_t argc;
    uint64_t argv;
    uint64_t envp;
    uint64_t kenv;
    uint64_t raw_tile_count;
    uint64_t raw_tile_ids[MAX_TILES * MAX_CHIPS];
} PACKED;

class Env : public BootEnv {
public:
    // set by TileMux
    uint64_t shared;

    uint64_t sp;
    uint64_t entry;
    uint64_t lambda;
    uint64_t heap_size;
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

    void format(OStream &os, const FormatSpecs &) const {
        format_to(os, "platform     : {}\n"_cf, platform);
        format_to(os, "tile_id      : {}\n"_cf, tile_id);
        format_to(os, "tile_desc    : {:#x}\n"_cf, tile_desc);
        format_to(os, "argc         : {}\n"_cf, argc);
        format_to(os, "argv         : {:p}\n"_cf, argv);
        format_to(os, "envp         : {:p}\n"_cf, envp);
        format_to(os, "kenv         : {:p}\n"_cf, kenv);
        format_to(os, "tiles        :\n"_cf);
        for(uint64_t i = 0; i < raw_tile_count; ++i)
            format_to(os, "  tile[{}] : {}\n"_cf, i, raw_tile_ids[i]);

        format_to(os, "shared       : {:#x}\n"_cf, shared);
        format_to(os, "sp           : {:p}\n"_cf, sp);
        format_to(os, "entry        : {:p}\n"_cf, entry);
        format_to(os, "lambda       : {:p}\n"_cf, lambda);
        format_to(os, "heap_size    : {:#x}\n"_cf, heap_size);
        format_to(os, "first_std_ep : {}\n"_cf, first_std_ep);
        format_to(os, "first_sel    : {}\n"_cf, first_sel);
        format_to(os, "act_id       : {}\n"_cf, act_id);
        format_to(os, "rmng_sel     : {}\n"_cf, rmng_sel);
        format_to(os, "pager_sess   : {}\n"_cf, pager_sess);
        format_to(os, "pager_sgate  : {}\n"_cf, pager_sgate);
        format_to(os, "mounts_addr  : {:p}\n"_cf, mounts_addr);
        format_to(os, "mounts_len   : {}\n"_cf, mounts_len);
        format_to(os, "fds_addr     : {}\n"_cf, fds_addr);
        format_to(os, "fds_len      : {:p}\n"_cf, fds_len);
        format_to(os, "data_addr    : {}\n"_cf, data_addr);
        format_to(os, "data_len     : {:p}\n"_cf, data_len);
    }
} PACKED;

#define ENV_SPACE_SIZE             (ENV_SIZE - (sizeof(word_t) * 2 + sizeof(m3::Env)))
#define ENV_SPACE_START(tile_desc) (tile_desc.env_space().first + sizeof(m3::Env))

static inline BootEnv *bootenv() {
#if defined(__m3lx__)
    // without further measures, the linker does not include the m3lx-specific initialization. as a
    // workaround we call a function of that compilation unit here when we are referring to one of
    // the mappings. as the TCU (needing the other mapping) also calls this function, this seems
    // good enough.
    (void)m3lx::tcu_fd();
#endif
    return reinterpret_cast<BootEnv *>(ENV_START);
}

}
