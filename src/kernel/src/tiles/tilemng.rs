/*
 * Copyright (C) 2020-2022 Nils Asmussen, Barkhausen Institut
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

use base::cell::{LazyStaticRefCell, RefMut, StaticCell};
use base::col::Vec;
use base::kif;
use base::tcu::TileId;

use crate::ktcu;
use crate::platform;
use crate::tiles::TileMux;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum State {
    RUNNING,
    DEINIT,
    SHUTDOWN,
}

static MUXES: LazyStaticRefCell<Vec<Vec<Option<TileMux>>>> = LazyStaticRefCell::default();
static STATE: StaticCell<State> = StaticCell::new(State::RUNNING);

pub fn state() -> State {
    STATE.get()
}

pub fn init() {
    deprivilege_tiles();

    let mut muxes = Vec::new();
    for tile in platform::user_tiles() {
        let cid = tile.chip() as usize;
        let tid = tile.tile() as usize;
        if cid >= muxes.len() {
            assert_eq!(cid, muxes.len());
            muxes.push(Vec::new());
        }
        while tid != muxes[cid].len() {
            muxes[cid].push(None);
        }
        muxes[cid].push(Some(TileMux::new(tile)));
    }
    MUXES.set(muxes);
}

pub fn deinit_async() {
    assert_eq!(STATE.get(), State::RUNNING);
    STATE.set(State::DEINIT);

    for tile in platform::user_tiles() {
        // ignore the tiles that are already shut down
        if tilemux(tile).is_initialized() {
            TileMux::reset_async(tile, None, None, false).ok();
        }
    }

    STATE.set(State::SHUTDOWN);
}

pub fn tilemux(tile: TileId) -> RefMut<'static, TileMux> {
    RefMut::map(MUXES.borrow_mut(), |muxes| {
        muxes[tile.chip() as usize][tile.tile() as usize]
            .as_mut()
            .unwrap()
    })
}

pub fn find_tile(tiledesc: &kif::TileDesc) -> Option<TileId> {
    platform::user_tiles().find(|&tile| {
        platform::tile_desc(tile).isa() == tiledesc.isa()
            && platform::tile_desc(tile).tile_type() == tiledesc.tile_type()
    })
}

fn deprivilege_tiles() {
    for tile in platform::user_tiles() {
        ktcu::deprivilege_tile(tile).expect("Unable to deprivilege tile");
    }
}
