/*
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

#include <base/Quota.h>
#include <base/TileDesc.h>
#include <base/time/Duration.h>
#include <base/util/Reference.h>

#include <m3/cap/ObjCap.h>

#include <utility>

namespace m3 {

/**
 * Represents a processing element.
 */
class Tile : public ObjCap, public RefCounted {
    explicit Tile(capsel_t sel, const TileDesc &desc, uint flags, bool free) noexcept
        : ObjCap(ObjCap::Tile, sel, flags),
          RefCounted(),
          _desc(desc),
          _free(free) {
    }

public:
    Tile(Tile &&tile) noexcept
        : ObjCap(std::move(tile)),
          RefCounted(std::move(tile)),
          _desc(tile._desc),
          _free(tile._free) {
        tile.flags(KEEP_CAP);
        tile._free = false;
    }
    ~Tile();

    /**
     * Allocate a new processing element
     *
     * @param desc the tile description
     * @param init whether the tile should be initialized with the appropriate multiplexer
     * @param inherit_pmp whether PMP EPs should be inherited from our tile
     * @return the tile object
     */
    static Reference<Tile> alloc(const TileDesc &desc, bool init = true, bool inherit_pmp = true);

    /**
     * Gets a tile with given description.
     *
     * The description is an '|' separated list of properties that will be tried in order. Two
     * special properties are supported:
     * - "own" to denote the own tile (provided that it has support for multiple activities)
     * - "clone" to denote a separate tile that is identical to the own tile
     * - "compat" to denote a separate tile that is compatible to the own tile (same ISA and type)
     *
     * For other properties, see `desc_with_properties` in tile.cc.
     *
     * Examples:
     * - tile with an arbitrary ISA, but preferred the own: "own|core"
     * - Identical tile, but preferred a separate one: "clone|own"
     * - Performance core if available, otherwise any core: "perf|core"
     * - Performance core with NIC if available, otherwise a efficiency core: "perf+nic|effi"
     *
     * @param desc the textual description of the tile
     * @param init whether the tile should be initialized with TileMux and PMP EPs should be
     *  inherited from our tile
     */
    static Reference<Tile> get(const char *desc, bool init = true);

    /**
     * Binds a tile object to the given selector and tile description
     *
     * @param sel the selector
     * @param desc the tile description
     * @return the tile object
     */
    static Reference<Tile> bind(capsel_t sel, const TileDesc &desc) {
        return Reference<Tile>(new Tile(sel, desc, KEEP_CAP, false));
    }

    /**
     * Derives a new tile object from the this by transferring a subset of the resources to the new
     * one
     *
     * @param eps the number of EPs to transfer (None = share the quota)
     * @param time the time slice length to transfer (None = share the quota)
     * @param pts the number of page tables to transfer (None = share the quota)
     * @return the new tile object
     */
    Reference<Tile> derive(Option<uint> eps = None, Option<TimeDuration> time = None,
                           Option<size_t> pts = None);

    /**
     * @return the number of endpoints available on this tile (via syscall)
     */
    size_t ep_count() const;

    /**
     * @return the multiplexer type that runs on this tile (via syscall)
     */
    KIF::Syscall::MuxType mux_type() const;

    /**
     * @return the description of the tile
     */
    const TileDesc &desc() const noexcept {
        return _desc;
    }

    /**
     * @return a tuple with the current EP quota, time quota and page-table quota
     */
    std::tuple<Quota<uint>, Quota<TimeDuration>, Quota<size_t>> quota() const;

    /**
     * Sets the quota of the tile with given selector to specified initial values.
     * This call requires a root tile capability.
     *
     * @param time the time slice length
     * @param pts the number of page tables
     */
    void set_quota(TimeDuration time, size_t pts);

private:
    TileDesc _desc;
    bool _free;
};

}
