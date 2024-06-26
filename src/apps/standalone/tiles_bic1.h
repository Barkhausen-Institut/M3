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

#define MODID_TILE0     0x04
#define MODID_TILE1     0x05
#define MODID_TILE2     0x06
#define MODID_TILE3     0x24
#define MODID_TILE4     0x25
#define MODID_TILE5     0x00
#define MODID_TILE6     0x01
#define MODID_TILE7     0x20
#define MODID_TILE8     0x21

#define MODID_PM0       MODID_TILE1
#define MODID_PM1       MODID_TILE4
#define MODID_PM2       MODID_TILE6
#define MODID_PM3       MODID_TILE8

#define MODID_C2C_WEST     MODID_TILE0
#define MODID_C2C_NORTH    MODID_TILE3
#define MODID_C2C_SOUTH    MODID_TILE5
#define MODID_C2C_EAST     MODID_TILE7

#define MODID_PERIPHERY    MODID_TILE2

enum class Tile {
    //this chip
    T0,
    T1,
    T2,
    T3,
    //other chip
    T4,
    T5,
    T6,
    T7,
};

static m3::TileId TILE_IDS[8] = {
    /* T0   */ m3::TileId(0, 0),
    /* T1   */ m3::TileId(0, 1),
    /* T2   */ m3::TileId(0, 2),
    /* T3   */ m3::TileId(0, 3),
    /* T4   */ m3::TileId(1, 0),
    /* T5   */ m3::TileId(1, 1),
    /* T6   */ m3::TileId(1, 2),
    /* T7   */ m3::TileId(1, 3),
};

static inline m3::Option<size_t> tile_idx(m3::TileId id) {
    for(size_t i = 0; i < ARRAY_SIZE(TILE_IDS); ++i) {
        if(TILE_IDS[i].raw() == id.raw())
            return m3::Some(i);
    }
    return m3::None;
}
