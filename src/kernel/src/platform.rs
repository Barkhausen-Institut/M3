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

use base::cell::LazyReadOnlyCell;
use base::cfg;
use base::col::Vec;
use base::env;
use base::goff;
use base::kif::{self, boot, Perm, TileDesc, TileISA, TileType};
use base::mem::{size_of, GlobAddr};
use base::tcu::{ActId, EpId, TileId, TCU, UNLIM_CREDITS};
use base::vec;

use crate::args;
use crate::ktcu;
use crate::mem::{self, MemMod, MemType};
use crate::tiles::KERNEL_ID;

const MAX_PHYS_ADDR_SIZE: u64 = 1 << 30;

pub struct KEnv {
    info: boot::Info,
    info_addr: GlobAddr,
    mods: Vec<boot::Mod>,
    tiles: Vec<Vec<boot::Tile>>,
}

impl KEnv {
    pub fn new(
        info: boot::Info,
        info_addr: GlobAddr,
        mods: Vec<boot::Mod>,
        tiles: Vec<Vec<boot::Tile>>,
    ) -> Self {
        KEnv {
            info,
            info_addr,
            mods,
            tiles,
        }
    }
}

static KENV: LazyReadOnlyCell<KEnv> = LazyReadOnlyCell::default();

fn get() -> &'static KEnv {
    KENV.get()
}

pub fn mods() -> &'static [boot::Mod] {
    &get().mods
}

pub fn info() -> &'static boot::Info {
    &get().info
}
pub fn info_addr() -> GlobAddr {
    get().info_addr
}
pub fn info_size() -> usize {
    size_of::<boot::Info>()
        + info().mod_count as usize * size_of::<boot::Mod>()
        + info().tile_count as usize * size_of::<boot::Tile>()
        + info().mem_count as usize * size_of::<boot::Mem>()
}

pub fn kernel_tile() -> TileId {
    TileId::new_from_raw(env::data().tile_id as u16)
}
pub fn user_tiles() -> impl Iterator<Item = TileId> {
    get()
        .tiles
        .iter()
        .flat_map(|chip| chip.iter())
        .filter(|t| { t.id } != kernel_tile() && t.desc.tile_type() != TileType::MEM)
        .map(|t| t.id)
}

pub fn tile_desc(id: TileId) -> TileDesc {
    get().tiles[id.chip() as usize][id.tile() as usize].desc
}

pub fn is_shared(id: TileId) -> bool {
    tile_desc(id).is_programmable()
}

pub fn init() {
    assert_eq!(env::data().tile_id, 0);

    // read kernel env
    let addr = GlobAddr::new(env::data().kenv);
    let mut offset = addr.offset();
    let info: boot::Info = ktcu::read_obj(addr.tile(), offset);
    offset += size_of::<boot::Info>() as goff;

    // read boot modules
    let mut mods: Vec<boot::Mod> = vec![boot::Mod::default(); info.mod_count as usize];
    ktcu::read_slice(addr.tile(), offset, &mut mods);
    offset += info.mod_count as goff * size_of::<boot::Mod>() as goff;

    // read tile ids
    let mut tile_ids: Vec<TileId> = vec![TileId::default(); info.tile_count as usize];
    ktcu::read_slice(addr.tile(), offset, &mut tile_ids);
    offset += info.tile_count as goff * size_of::<TileId>() as goff;

    // read tile descriptors
    let mut tile_descs: Vec<TileDesc> = vec![TileDesc::default(); info.tile_count as usize];
    ktcu::read_slice(addr.tile(), offset, &mut tile_descs);
    offset += info.tile_count as goff * size_of::<TileDesc>() as goff;

    // read memory regions
    let mut mems: Vec<boot::Mem> = vec![boot::Mem::default(); info.mem_count as usize];
    ktcu::read_slice(addr.tile(), offset, &mut mems);

    // build new info for user tiles
    let mut uinfo = boot::Info {
        mod_count: info.mod_count,
        tile_count: info.tile_count,
        mem_count: info.mem_count,
        serv_count: 0,
    };

    let mut umems = Vec::new();
    let mut utiles = Vec::new();
    let mut tiles = Vec::new();

    // register memory modules
    let mut kmem_idx = 0;
    let mut mem = mem::borrow_mut();
    let all_tiles = tile_ids
        .iter()
        .zip(tile_descs.iter())
        .map(|(id, desc)| boot::Tile::new(*id, *desc));
    for tile in all_tiles {
        if tile.desc.tile_type() == TileType::MEM {
            // the first memory module hosts the boot modules and tile-specific memory areas
            if kmem_idx == 0 {
                let avail = mems[kmem_idx].size();
                if avail <= args::get().kmem as goff {
                    panic!("Not enough DRAM for kernel memory ({})", args::get().kmem);
                }

                // boot modules
                let last_mod = mods.last().unwrap();
                let mods_end = (last_mod.addr() + last_mod.size).offset();
                // ensure that we can actually reach the memory with 30-bit physical addresses
                assert!(mods_end < MAX_PHYS_ADDR_SIZE);
                mem.add(MemMod::new(MemType::OCCUPIED, tile.id, 0, mods_end));
                umems.push(boot::Mem::new(
                    GlobAddr::new_with(tile.id, 0),
                    mods_end,
                    true,
                ));

                // kernel memory
                let mut used = tile.desc.mem_size() as goff - avail;
                let kmem = MemMod::new(MemType::KERNEL, tile.id, used, args::get().kmem as goff);
                used += args::get().kmem as goff;
                // configure EP to give us access to this range of physical memory
                ktcu::config_local_ep(1, |regs| {
                    ktcu::config_mem(
                        regs,
                        KERNEL_ID,
                        kmem.addr().tile(),
                        kmem.addr().offset(),
                        kmem.capacity() as usize,
                        Perm::RW,
                    );
                });
                mem.add(kmem);

                // root memory
                mem.add(MemMod::new(
                    MemType::ROOT,
                    tile.id,
                    used,
                    cfg::FIXED_ROOT_MEM as goff,
                ));
                used += cfg::FIXED_ROOT_MEM as goff;

                // user memory
                let user_size = core::cmp::min(MAX_PHYS_ADDR_SIZE, avail);
                mem.add(MemMod::new(MemType::USER, tile.id, used, user_size));
                umems.push(boot::Mem::new(
                    GlobAddr::new_with(tile.id, used),
                    user_size - args::get().kmem as goff,
                    false,
                ));
            }
            else {
                let user_size = core::cmp::min(MAX_PHYS_ADDR_SIZE, tile.desc.mem_size() as goff);
                mem.add(MemMod::new(MemType::USER, tile.id, 0, user_size));
                umems.push(boot::Mem::new(
                    GlobAddr::new_with(tile.id, 0),
                    user_size,
                    false,
                ));
            }
            kmem_idx += 1;
        }
        else {
            utiles.push(tile);
        }

        let cid = { tile.id }.chip() as usize;
        let tid = { tile.id }.tile() as usize;
        if cid >= tiles.len() {
            assert_eq!(cid, tiles.len());
            tiles.push(Vec::new());
        }
        assert_eq!(tid, tiles[cid].len());
        tiles[cid].push(tile);
    }

    // write-back boot info
    let mut uoffset = addr.offset();
    uinfo.tile_count = (utiles.len() - 1) as u64;
    uinfo.mem_count = umems.len() as u64;
    ktcu::write_slice(addr.tile(), uoffset, &[uinfo]);
    uoffset += size_of::<boot::Info>() as goff;
    uoffset += info.mod_count as goff * size_of::<boot::Mod>() as goff;

    // write-back user tiles
    ktcu::write_slice(addr.tile(), uoffset, &utiles[1..]);
    uoffset += uinfo.tile_count as goff * size_of::<boot::Tile>() as goff;

    // write-back user memory regions
    ktcu::write_slice(addr.tile(), uoffset, &umems);

    KENV.set(KEnv::new(info, addr, mods, tiles));
}

pub fn init_serial(dest: Option<(TileId, EpId)>) {
    if env::data().platform == env::Platform::HW.val {
        let (tile, ep) = dest.unwrap_or((TileId::default(), 0));
        let serial = GlobAddr::new(env::data().kenv + 16 * 1024 * 1024);
        let tile_modid = TCU::tileid_to_nocid(tile);
        ktcu::write_slice(serial.tile(), serial.offset(), &[
            tile_modid as u64,
            ep as u64,
        ]);
    }
    else if let Some(ser_tile) =
        user_tiles().find(|idx| tile_desc(*idx).isa() == TileISA::SERIAL_DEV)
    {
        if let Some((tile, ep)) = dest {
            ktcu::config_remote_ep(ser_tile, 4, |regs| {
                let act = kif::tilemux::ACT_ID as ActId;
                ktcu::config_send(regs, act, 0, tile, ep, cfg::SERIAL_BUF_ORD, UNLIM_CREDITS);
            })
            .unwrap();
        }
        else {
            ktcu::invalidate_ep_remote(ser_tile, 4, true).unwrap();
        }
    }
}
