/*
 * Copyright (C) 2022 Nils Asmussen, Barkhausen Institut
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

#include <m3/Exception.h>
#include <m3/Syscalls.h>
#include <m3/session/ResMng.h>
#include <m3/tiles/Activity.h>
#include <m3/tiles/Tile.h>

namespace m3 {

constexpr size_t MAX_DESC_LEN = 256;

static TileDesc desc_with_properties(TileDesc desc, const char *props) {
    char props_cpy[MAX_DESC_LEN];
    if(strlen(props) >= MAX_DESC_LEN)
        vthrow(Errors::NO_SPACE, "Tile description too long"_cf);
    strcpy(props_cpy, props);

    auto res = desc;
    char *prop = strtok(props_cpy, "+");
    while(prop != nullptr) {
        if(strcmp(prop, "x86") == 0)
            res = TileDesc(res.type(), TileISA::X86, 0);
        else if(strcmp(prop, "riscv32") == 0)
            res = TileDesc(res.type(), TileISA::RISCV32, 0);
        else if(strcmp(prop, "riscv64") == 0)
            res = TileDesc(res.type(), TileISA::RISCV64, 0);
        else if(strcmp(prop, "effi") == 0)
            res = TileDesc(res.type(), res.isa(), 0, res.attr() | TileAttr::EFFI);
        else if(strcmp(prop, "perf") == 0)
            res = TileDesc(res.type(), res.isa(), 0, res.attr() | TileAttr::PERF);
        else if(strcmp(prop, "nic") == 0)
            res = TileDesc(res.type(), res.isa(), 0, res.attr() | TileAttr::NIC);
        else if(strcmp(prop, "serial") == 0)
            res = TileDesc(res.type(), res.isa(), 0, res.attr() | TileAttr::SERIAL);
        else if(strcmp(prop, "kecacc") == 0)
            res = TileDesc(res.type(), res.isa(), 0, res.attr() | TileAttr::KECACC);
        else if(strcmp(prop, "indir") == 0)
            res = TileDesc(TileType::COMP, TileISA::ACCEL_INDIR, 0, TileAttr::IMEM);
        else if(strcmp(prop, "copy") == 0)
            res = TileDesc(TileType::COMP, TileISA::ACCEL_COPY, 0, TileAttr::IMEM);
        else if(strcmp(prop, "rot13") == 0)
            res = TileDesc(TileType::COMP, TileISA::ACCEL_ROT13, 0, TileAttr::IMEM);
        else if(strcmp(prop, "idedev") == 0)
            res = TileDesc(TileType::COMP, TileISA::IDE_DEV, 0, TileAttr::IMEM);
        else if(strcmp(prop, "nicdev") == 0)
            res = TileDesc(TileType::COMP, TileISA::NIC_DEV, 0, TileAttr::IMEM);
        else if(strcmp(prop, "serdev") == 0)
            res = TileDesc(TileType::COMP, TileISA::SERIAL_DEV, 0, TileAttr::IMEM);
        prop = strtok(NULL, "+");
    }
    return res;
}

Tile::~Tile() {
    if(_free) {
        try {
            Activity::own().resmng()->free_tile(sel());
        }
        catch(...) {
            // ignore
        }
    }
}

Reference<Tile> Tile::alloc(const TileDesc &desc, bool init) {
    capsel_t sel = SelSpace::get().alloc_sel();
    TileDesc res = Activity::own().resmng()->alloc_tile(sel, desc, init);
    return Reference<Tile>(new Tile(sel, res, KEEP_CAP, true));
}

Reference<Tile> Tile::get(const char *desc, bool init) {
    char desc_cpy[MAX_DESC_LEN];
    if(strlen(desc) >= MAX_DESC_LEN)
        vthrow(Errors::NO_SPACE, "Properties description too long"_cf);
    strcpy(desc_cpy, desc);

    auto own = Activity::own().tile();
    char *props = strtok(desc_cpy, "|");
    while(props != nullptr) {
        if(strcmp(props, "own") == 0) {
            if(own->desc().supports_tilemux() && own->desc().has_virtmem())
                return own;
        }
        else if(strcmp(props, "clone") == 0) {
            // on m3lx, we don't support "clone", because the required semantics are difficult to
            // support. At first, being a clone requires to have the same multiplexer type, i.e.,
            // Linux again. And the semantics of Tile::get("clone") are that we get a new tile for
            // ourself, which would require us to boot up a new Linux instance. This takes simply
            // too long to do that dynamically, IMO. Therefore, the most sensible way to handle
            // "clone" on m3lx is to let it always fail. Meaning, applications should provide "own"
            // as a fallback.
#if !defined(__m3lx__)
            try {
                return Tile::alloc(own->desc(), init);
            }
            catch(...) {
            }
#endif
        }
        else if(strcmp(props, "compat") == 0) {
            // same as for "clone"
#if !defined(__m3lx__)
            try {
                auto type_isa = TileDesc(own->desc().type(), own->desc().isa(), 0);
                return Tile::alloc(type_isa, init);
            }
            catch(...) {
            }
#endif
        }
        else {
            auto base = TileDesc(own->desc().type(), own->desc().isa(), 0);
            try {
                return Tile::alloc(desc_with_properties(base, props), init);
            }
            catch(...) {
            }
        }
        props = strtok(NULL, "|");
    }
    vthrow(Errors::NOT_FOUND, "Unable to find tile with {}"_cf, desc);
}

Reference<Tile> Tile::derive(Option<uint> eps, Option<TimeDuration> time, Option<size_t> pts) {
    capsel_t sel = SelSpace::get().alloc_sel();
    Syscalls::derive_tile(this->sel(), sel, eps, time, pts);
    return Reference<Tile>(new Tile(sel, desc(), 0, false));
}

size_t Tile::ep_count() const {
    auto [mux_type, id, desc, ep_count] = Syscalls::tile_info(sel());
    return ep_count;
}

KIF::Syscall::MuxType Tile::mux_type() const {
    auto [mux_type, id, desc, ep_count] = Syscalls::tile_info(sel());
    return mux_type;
}

std::tuple<Quota<uint>, Quota<TimeDuration>, Quota<size_t>> Tile::quota() const {
    return Syscalls::tile_quota(sel());
}

void Tile::set_quota(TimeDuration time, size_t pts) {
    Syscalls::tile_set_quota(sel(), time, pts);
}

}
