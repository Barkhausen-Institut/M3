/*
 * Copyright (C) 2024 Nils Asmussen, Barkhausen Institut
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

use m3::errors::Error;
use m3::io::LogFlags;
use m3::mem::VirtAddr;
use m3::tiles::{Activity, ActivityArgs, ChildActivity, Tile};
use m3::time::{CycleDuration, CycleInstant, Duration};
use m3::{cfg, log};

pub fn create_activity<S: AsRef<str>>(name: S) -> Result<ChildActivity, Error> {
    let tile = Tile::get("compat")?;
    ChildActivity::new_with(tile, ActivityArgs::new(name.as_ref()))
}

pub fn compute_for(name: &str, duration: CycleDuration) {
    log!(LogFlags::Debug, "{}: computing for {:?}", name, duration);

    let end = CycleInstant::now().as_cycles() + duration.as_raw();
    while CycleInstant::now().as_cycles() < end {}
}

pub fn buffer_addr() -> VirtAddr {
    // TODO that's a bit of guess work here; at some point we might want to have an abstraction in
    // libm3 that manages our address space or so.
    let tile_desc = Activity::own().tile_desc();
    if tile_desc.has_virtmem() {
        VirtAddr::new(0x3000_0000)
    }
    else {
        VirtAddr::from(cfg::MEM_OFFSET + tile_desc.mem_size() / 2)
    }
}
