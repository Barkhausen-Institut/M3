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

#include <base/TCU.h>
#include <base/util/Option.h>

enum Tile {
    T0,
    T1,
    T2,
    T3,
    T4,
    T5,
    T6,
    T7,
    MEM,
};

// clang-format off
static m3::TileId TILE_IDS[9] = {
    // TODO parse the actual configuration from the boot environment
    /* T0  */ m3::TileId(0, 0),
    /* T1  */ m3::TileId(0, 1),
    /* T2  */ m3::TileId(0, 2),
    /* T3  */ m3::TileId(0, 3),
    /* T4  */ m3::TileId(0, 4),
    /* T5  */ m3::TileId(0, 5),
    /* T6  */ m3::TileId(0, 6),
    /* T7  */ m3::TileId(0, 7),
    /* MEM */ m3::TileId(0, 8),
};
// clang-format on

static inline m3::Option<size_t> tile_idx(m3::TileId id) {
    for(size_t i = 0; i < ARRAY_SIZE(TILE_IDS); ++i) {
        if(TILE_IDS[i].raw() == id.raw())
            return m3::Some(i);
    }
    return m3::None;
}
