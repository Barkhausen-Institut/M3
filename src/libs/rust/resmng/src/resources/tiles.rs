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

use m3::cell::{Cell, Ref, RefCell, RefMut};
use m3::cfg;
use m3::col::Vec;
use m3::com::MemGate;
use m3::elf;
use m3::env;
use m3::errors::{Code, Error};
use m3::io::LogFlags;
use m3::kif::{Perm, TileDesc, INVALID_SEL};
use m3::log;
use m3::mem::{size_of, GlobOff};
use m3::rc::Rc;
use m3::syscalls;
use m3::tcu::{EpId, TileId};
use m3::tiles::Tile;
use m3::time::TimeDuration;
use m3::util::math;

use crate::resources::memory::Allocation;

// PMP EPs start at 1, because 0 is reserved for TileMux
const FIRST_FREE_PMP_EP: EpId = 1;

// The hardcoded location of the DTB as expected by bbl
const DTB_OFFSET: usize = 0x1FF000;

#[derive(Debug)]
struct Mux {
    mem: MemGate,
    alloc: Option<Allocation>,
}

#[derive(Debug)]
pub struct TileState {
    tile: Rc<Tile>,
    next_pmp_ep: EpId,
    pmp_regions: Vec<(MemGate, usize)>,
    mux: Option<Mux>,
}

impl TileState {
    fn new(tile: Rc<Tile>) -> Self {
        Self {
            tile,
            next_pmp_ep: FIRST_FREE_PMP_EP,
            pmp_regions: Vec::new(),
            mux: None,
        }
    }

    pub fn add_mem_region(
        &mut self,
        mgate: MemGate,
        size: usize,
        set: bool,
        overwrite: bool,
    ) -> Result<(), Error> {
        if set {
            loop {
                match syscalls::tile_set_pmp(
                    self.tile.sel(),
                    mgate.sel(),
                    self.next_pmp_ep,
                    overwrite,
                ) {
                    Err(e) if e.code() == Code::Exists && !overwrite => self.next_pmp_ep += 1,
                    Err(e) => return Err(e),
                    Ok(_) => break,
                }
            }
            self.next_pmp_ep += 1;
        }
        self.pmp_regions.push((mgate, size));
        Ok(())
    }

    pub fn inherit_mem_regions(&mut self, tile: &TileUsage) -> Result<(), Error> {
        for (mgate, size) in tile.state().pmp_regions.iter() {
            self.add_mem_region(mgate.derive(0, *size, Perm::RWX)?, *size, true, true)?;
        }
        Ok(())
    }

    fn copy_data(
        buf: &mut [u8],
        src: &MemGate,
        dst: &MemGate,
        src_off: usize,
        dst_off: usize,
        size: usize,
    ) -> Result<(), Error> {
        let mut pos = 0;
        while pos < size {
            let amount = (size - pos).min(buf.len());
            src.read(&mut buf[0..amount], (src_off + pos) as GlobOff)?;
            dst.write(&buf[0..amount], (dst_off + pos) as GlobOff)?;
            pos += amount;
        }
        Ok(())
    }

    pub fn load_mux<A, M>(
        &mut self,
        name: &str,
        mem_size: usize,
        initrd: Option<&str>,
        dtb: Option<&str>,
        alloc_mem: A,
        mut get_mod: M,
    ) -> Result<(), Error>
    where
        A: FnOnce(usize) -> Result<(MemGate, Option<Allocation>), Error>,
        M: FnMut(&str) -> Result<MemGate, Error>,
    {
        if self.mux.is_some() {
            return Ok(());
        }

        let mux = match self.tile.memory() {
            Ok(mem) => Mux { mem, alloc: None },
            Err(_) => {
                let (mem, alloc) = alloc_mem(mem_size)?;
                Mux { mem, alloc }
            },
        };
        let mux_elf = get_mod(name)?;
        let mem_region = mux.mem.region()?;

        log!(
            LogFlags::ResMngTiles,
            "Loading multiplexer '{}' to ({}, {}M) for {}",
            name,
            mem_region.0,
            mem_region.1 / (1024 * 1024),
            self.tile.id(),
        );

        let hdr: elf::ElfHeader = mux_elf.read_obj(0)?;

        if hdr.ident[0] != b'\x7F'
            || hdr.ident[1] != b'E'
            || hdr.ident[2] != b'L'
            || hdr.ident[3] != b'F'
        {
            return Err(Error::new(Code::InvalidElf));
        }

        let zeros = m3::vec![0u8; 4096];
        let mut buf = m3::vec![0u8; 4096];

        let mut off = hdr.ph_off;
        for _ in 0..hdr.ph_num {
            // load program header
            let phdr: elf::ProgramHeader = mux_elf.read_obj(off as GlobOff)?;
            off += hdr.ph_entry_size as usize;

            // we're only interested in non-empty load segments
            if phdr.ty != elf::PHType::Load.into() || phdr.mem_size == 0 {
                continue;
            }

            // load segment from boot module
            let phys = phdr.phys_addr - cfg::MEM_OFFSET;
            Self::copy_data(
                &mut buf,
                &mux_elf,
                &mux.mem,
                phdr.offset as usize,
                phys,
                phdr.file_size as usize,
            )?;

            // zero the remaining memory
            let mut segpos = phdr.file_size as usize;
            while segpos < phdr.mem_size as usize {
                let amount = (phdr.mem_size as usize - segpos).min(buf.len());
                mux.mem
                    .write(&zeros[0..amount], (phys + segpos) as GlobOff)?;
                segpos += amount;
            }
        }

        // load initrd to the end of the memory region
        if let Some(initrd) = initrd {
            let rd_mod = get_mod(initrd)?;
            let rd_size = rd_mod.region()?.1 as usize;
            let rd_start = mem_size - math::round_up(rd_size, cfg::PAGE_SIZE);

            log!(
                LogFlags::ResMngTiles,
                "Loading initrd '{}' with {}b to {:#x}",
                initrd,
                rd_size,
                cfg::MEM_OFFSET + rd_start
            );

            Self::copy_data(&mut buf, &rd_mod, &mux.mem, 0, rd_start, rd_size)?;
        }

        // load dtb to the expected location
        if let Some(dtb) = dtb {
            let dtb_mod = get_mod(dtb)?;
            let dtb_size = dtb_mod.region()?.1 as usize;
            // the payload of bbl starts one page behind the dtb
            assert!(dtb_size <= cfg::PAGE_SIZE);

            log!(
                LogFlags::ResMngTiles,
                "Loading dtb '{}' with {}b to {:#x}",
                dtb,
                dtb_size,
                cfg::MEM_OFFSET + DTB_OFFSET
            );

            Self::copy_data(&mut buf, &dtb_mod, &mux.mem, 0, DTB_OFFSET, dtb_size)?;
        }

        // pass env vars to multiplexer
        let mut off = cfg::ENV_START + size_of::<env::BaseEnv>();
        let envp = env::write_args(
            &env::vars_raw(),
            &mux.mem,
            &mut off,
            cfg::MEM_OFFSET as GlobOff,
        )?;

        // init environment
        let env = env::BootEnv {
            platform: env::boot().platform,
            envp: envp.as_raw(),
            tile_id: self.tile.id().raw() as u64,
            tile_desc: self.tile.desc().value(),
            raw_tile_count: env::boot().raw_tile_count,
            raw_tile_ids: env::boot().raw_tile_ids,
            ..Default::default()
        };
        mux.mem
            .write_obj(&env, (cfg::ENV_START - cfg::MEM_OFFSET).as_goff())?;

        syscalls::tile_reset(self.tile.sel(), mux.mem.sel())?;

        self.mux = Some(mux);
        Ok(())
    }

    pub fn unload_mux<F>(&mut self, free: F) -> Result<(), Error>
    where
        F: FnOnce(Allocation),
    {
        // reset the tile before we drop the MemGate for its PMP EP
        if let Some(mux) = self.mux.take() {
            syscalls::tile_reset(self.tile.sel(), INVALID_SEL)?;
            if let Some(alloc) = mux.alloc {
                free(alloc);
            }
        }
        Ok(())
    }
}

impl Drop for TileState {
    fn drop(&mut self) {
        self.unload_mux(|_alloc| panic!("Mux memory not freed before dropping tile"))
            .unwrap();
    }
}

#[derive(Clone, Debug)]
pub struct TileUsage {
    idx: Option<usize>,
    state: Rc<RefCell<TileState>>,
    tile: Rc<Tile>,
}

impl TileUsage {
    fn new(idx: usize, tile: Rc<Tile>) -> Self {
        Self {
            idx: Some(idx),
            state: Rc::new(RefCell::new(TileState::new(tile.clone()))),
            tile,
        }
    }

    pub fn new_obj(tile: Rc<Tile>) -> Self {
        Self {
            idx: None,
            state: Rc::new(RefCell::new(TileState::new(tile.clone()))),
            tile,
        }
    }

    pub fn index(&self) -> Option<usize> {
        self.idx
    }

    pub fn tile_id(&self) -> TileId {
        self.tile.id()
    }

    pub fn tile_obj(&self) -> &Rc<Tile> {
        &self.tile
    }

    pub fn state(&self) -> Ref<'_, TileState> {
        self.state.borrow()
    }

    pub fn state_mut(&mut self) -> RefMut<'_, TileState> {
        self.state.borrow_mut()
    }

    pub fn derive(
        &self,
        eps: Option<u32>,
        bw: Option<u32>,
        time: Option<TimeDuration>,
        pts: Option<usize>,
    ) -> Result<TileUsage, Error> {
        let tile = self.tile_obj().derive(eps, bw, time, pts)?;
        let _quota = tile.quota().unwrap();
        log!(
            LogFlags::ResMngTiles,
            "Deriving {}: (eps={:?}, bw={:?}, time={:?}, pts={:?})",
            self.tile_id(),
            _quota.mem_bw(),
            _quota.endpoints(),
            _quota.time(),
            _quota.page_tables(),
        );
        Ok(TileUsage {
            idx: self.idx,
            state: self.state.clone(),
            tile,
        })
    }
}

struct ManagedTile {
    id: TileId,
    tile: Rc<Tile>,
    users: Cell<u32>,
}

impl ManagedTile {
    fn add_user(&self) -> u32 {
        let old = self.users.get();
        self.users.set(old + 1);
        old
    }

    fn remove_user(&self) -> u32 {
        self.users.replace(self.users.get() - 1)
    }
}

#[derive(Default)]
pub struct TileManager {
    tiles: Vec<ManagedTile>,
}

impl TileManager {
    pub fn count(&self) -> usize {
        self.tiles.len()
    }

    pub fn get(&self, idx: usize) -> Rc<Tile> {
        self.tiles[idx].tile.clone()
    }

    pub fn add(&mut self, tile: Rc<Tile>) {
        self.tiles.push(ManagedTile {
            id: tile.id(),
            tile,
            users: Cell::from(0),
        });
    }

    pub fn add_user(&self, usage: &TileUsage) {
        if let Some(idx) = usage.idx {
            if self.tiles[idx].add_user() == 0 {
                log!(
                    LogFlags::ResMngTiles,
                    "Allocating {}: {:?} (eps={:?})",
                    self.tiles[idx].id,
                    self.tiles[idx].tile.desc(),
                    self.get(idx).quota().unwrap().endpoints(),
                );
            }
        }
    }

    pub fn remove_user(&self, usage: &TileUsage) {
        if let Some(idx) = usage.idx {
            if self.tiles[idx].remove_user() == 1 {
                log!(
                    LogFlags::ResMngTiles,
                    "Freeing {}: {:?}",
                    self.tiles[idx].id,
                    self.tiles[idx].tile.desc()
                );
            }
        }
    }

    pub fn find(&self, desc: TileDesc) -> Result<TileUsage, Error> {
        for (id, tile) in self.tiles.iter().enumerate() {
            if tile.users.get() == 0
                && tile.tile.desc().isa() == desc.isa()
                && tile.tile.desc().tile_type() == desc.tile_type()
                && (tile.tile.desc().attr() & desc.attr()) == desc.attr()
            {
                return Ok(TileUsage::new(id, tile.tile.clone()));
            }
        }
        log!(LogFlags::ResMngTiles, "Unable to find tile with {:?}", desc);
        Err(Error::new(Code::NotFound))
    }

    pub fn find_with_attr(&self, base: TileDesc, attr: &str) -> Result<TileUsage, Error> {
        for props in attr.split('|') {
            if let Ok(usage) = self.find(base.with_properties(props)) {
                return Ok(usage);
            }
        }
        log!(
            LogFlags::ResMngTiles,
            "Unable to find tile with attributes {}",
            attr
        );
        Err(Error::new(Code::NotFound))
    }
}
