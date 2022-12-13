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

use base::cell::StaticCell;
use base::cfg;
use base::col::{String, Vec};
use base::envdata;
use base::goff;
use base::kif::{self, boot, Perm, TileDesc, TileISA, TileType};
use base::mem::{size_of, GlobAddr};
use base::tcu::{ActId, EpId, TileId, TCU, UNLIM_CREDITS};
use base::vec;

use crate::args;
use crate::ktcu;
use crate::mem::{self, MemMod, MemType};
use crate::platform::{self, tile_desc};
use crate::tiles::KERNEL_ID;

static LAST_TILE: StaticCell<TileId> = StaticCell::new(0);

pub fn init(_args: &[String]) -> platform::KEnv {
    // read kernel env
    let addr = GlobAddr::new(envdata::get().kenv);
    let mut offset = addr.offset();
    let mut info: boot::Info = ktcu::read_obj(addr.tile(), offset);
    offset += size_of::<boot::Info>() as goff;

    // read boot modules
    let mut mods: Vec<boot::Mod> = vec![boot::Mod::default(); info.mod_count as usize];
    ktcu::read_slice(addr.tile(), offset, &mut mods);
    offset += info.mod_count as goff * size_of::<boot::Mod>() as goff;

    // read tiles
    let mut tiles: Vec<TileDesc> = vec![TileDesc::default(); info.tile_count as usize];
    ktcu::read_slice(addr.tile(), offset, &mut tiles);
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

    // register memory modules
    let mut kmem_idx = 0;
    let mut mem = mem::borrow_mut();
    for (i, tile) in tiles.iter().enumerate() {
        if tile.tile_type() == TileType::MEM {
            // the first memory module hosts the FS image and other stuff
            if kmem_idx == 0 {
                let avail = mems[kmem_idx].size();
                if avail <= args::get().kmem as goff {
                    panic!("Not enough DRAM for kernel memory ({})", args::get().kmem);
                }

                // file system image
                let modoff = 0x1800_0000 + 0x5000_0000; // see tcu_fs.py
                mem.add(MemMod::new(MemType::OCCUPIED, i as TileId, 0, modoff));
                umems.push(boot::Mem::new(
                    GlobAddr::new_with(i as TileId, 0),
                    modoff,
                    true,
                ));

                // boot modules
                let mut used = tile.mem_size() as goff - avail;
                let modsize = used - modoff;
                mem.add(MemMod::new(MemType::BOOT, i as TileId, modoff, modsize));
                umems.push(boot::Mem::new(
                    GlobAddr::new_with(i as TileId, modoff),
                    modsize,
                    true,
                ));

                // kernel memory
                let kmem =
                    MemMod::new(MemType::KERNEL, i as TileId, used, args::get().kmem as goff);
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
                    i as TileId,
                    used,
                    cfg::FIXED_ROOT_MEM as goff,
                ));
                used += cfg::FIXED_ROOT_MEM as goff;

                // user memory
                let user_size = core::cmp::min((1 << 30) - cfg::PAGE_SIZE as goff, avail);
                mem.add(MemMod::new(MemType::USER, i as TileId, used, user_size));
                umems.push(boot::Mem::new(
                    GlobAddr::new_with(i as TileId, used),
                    user_size - args::get().kmem as goff,
                    false,
                ));
            }
            else {
                let user_size =
                    core::cmp::min((1 << 30) - cfg::PAGE_SIZE as usize, tile.mem_size());
                mem.add(MemMod::new(
                    MemType::USER,
                    i as TileId,
                    0,
                    user_size as goff,
                ));
                umems.push(boot::Mem::new(
                    GlobAddr::new_with(i as TileId, 0),
                    user_size as goff,
                    false,
                ));
            }
            kmem_idx += 1;
        }
        else {
            if kmem_idx > 0 {
                panic!("All memory tiles have to be last");
            }

            LAST_TILE.set(i as TileId);

            if i > 0 {
                assert!(kernel_tile() == 0);
                utiles.push(boot::Tile::new(i as u32, *tile));
            }
        }
    }

    // write-back boot info
    let mut uoffset = addr.offset();
    uinfo.tile_count = utiles.len() as u64;
    uinfo.mem_count = umems.len() as u64;
    info.mem_count = umems.len() as u64;
    ktcu::write_slice(addr.tile(), uoffset, &[uinfo]);
    uoffset += size_of::<boot::Info>() as goff;
    uoffset += info.mod_count as goff * size_of::<boot::Mod>() as goff;

    // write-back user tiles
    ktcu::write_slice(addr.tile(), uoffset, &utiles);
    uoffset += uinfo.tile_count as goff * size_of::<boot::Tile>() as goff;

    // write-back user memory regions
    ktcu::write_slice(addr.tile(), uoffset, &umems);

    platform::KEnv::new(info, addr, mods, tiles)
}

pub fn init_serial(dest: Option<(TileId, EpId)>) {
    if envdata::get().platform == envdata::Platform::HW.val {
        let (tile, ep) = dest.unwrap_or((0, 0));
        let serial = GlobAddr::new(envdata::get().kenv + 16 * 1024 * 1024);
        let tile_modid = TCU::tileid_to_nocid(tile);
        ktcu::write_slice(serial.tile(), serial.offset(), &[
            tile_modid as u64,
            ep as u64,
        ]);
    }
    else if let Some(ser_tile) = user_tiles().find(|i| tile_desc(*i).isa() == TileISA::SERIAL_DEV)
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

pub fn kernel_tile() -> TileId {
    envdata::get().tile_id as TileId
}
pub fn user_tiles() -> platform::TileIterator {
    platform::TileIterator::new(kernel_tile() + 1, LAST_TILE.get())
}

pub fn is_shared(tile: TileId) -> bool {
    platform::tile_desc(tile).is_programmable()
}

pub fn rbuf_tilemux(_tile: TileId) -> goff {
    cfg::TILEMUX_RBUF_SPACE as goff
}
