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

use base::cfg::{ENV_START, MEM_OFFSET, MOD_HEAP_SIZE, PAGE_BITS, PAGE_MASK, PAGE_SIZE};
use base::elf;
use base::env;
use base::errors::{Code, Error};
use base::goff;
use base::io::LogFlags;
use base::kif::{self, PageFlags};
use base::log;
use base::mem::{size_of, GlobAddr};
use base::tcu;
use base::util::math;

use crate::cap::{Capability, KObject, MapObject, SelRange};
use crate::ktcu;
use crate::mem;
use crate::tiles::{tilemng, Activity, TileMux};

use crate::platform;

trait ELFLoader {
    #[allow(m3_async::no_async_call)]
    fn load_segment_async(
        &mut self,
        virt: goff,
        phys: GlobAddr,
        size: usize,
        flags: PageFlags,
        map: bool,
    ) -> Result<(), Error>;

    #[allow(m3_async::no_async_call)]
    fn zero_segment_async(
        &mut self,
        virt: goff,
        size: usize,
        flags: PageFlags,
    ) -> Result<(), Error>;

    #[allow(m3_async::no_async_call)]
    fn map_heap_async(&mut self, _virt: goff) -> Result<(), Error> {
        Ok(())
    }

    #[allow(m3_async::no_async_call)]
    fn map_stack_async(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

pub fn init_activity_async(act: &Activity) -> Result<i32, Error> {
    let mut loader = ActivityELFLoader(act);

    // put mapping for env into cap table (so that we can access it in create_mgate later)
    let env_phys = if platform::tile_desc(act.tile_id()).has_virtmem() {
        let mut env_addr = TileMux::translate_async(
            tilemng::tilemux(act.tile_id()),
            act.id(),
            ENV_START as goff,
            kif::PageFlags::RW,
        )?;
        env_addr = env_addr + (ENV_START & PAGE_MASK) as goff;

        let flags = PageFlags::from(kif::Perm::RW);
        loader.load_segment_async(ENV_START as goff, env_addr, PAGE_SIZE, flags, false)?;

        ktcu::glob_to_phys_remote(act.tile_id(), env_addr, flags)?
    }
    else {
        ENV_START as goff
    };

    if act.is_root() {
        load_root_async(loader, env_phys)?;
    }
    Ok(0)
}

pub fn load_mux_async(tile: tcu::TileId, mem: &mem::Allocation) -> Result<(), Error> {
    let app = get_mod("tilemux").ok_or_else(|| Error::new(Code::NoSuchFile))?;
    log!(
        LogFlags::KernActs,
        "Loading multiplexer '{}' onto {}",
        app.name(),
        tile
    );

    // load multiplexer into memory
    let mut loader = MetalELFLoader::new(mem.global(), MEM_OFFSET as goff);
    load_mod_async(&mut loader, app)?;

    // write env vars
    let env_phys = mem.global().offset() + ENV_START as goff - MEM_OFFSET as goff;
    let mut env_off = size_of::<env::BaseEnv>();
    let envp_addr = write_arguments(
        &env::vars_raw(),
        mem.global().tile(),
        env_phys,
        &mut env_off,
    );

    // load environment into memory
    let env = env::BootEnv {
        platform: env::boot().platform,
        envp: envp_addr as u64,
        tile_id: tile.raw() as u64,
        tile_desc: platform::tile_desc(tile).value(),
        raw_tile_count: env::boot().raw_tile_count,
        raw_tile_ids: env::boot().raw_tile_ids,
        ..Default::default()
    };
    ktcu::write_slice(mem.global().tile(), env_phys, &[env]);

    Ok(())
}

fn load_root_async(mut loader: ActivityELFLoader<'_>, env_phys: goff) -> Result<(), Error> {
    let entry: usize = {
        let app = get_mod("root").ok_or_else(|| Error::new(Code::NoSuchFile))?;
        log!(LogFlags::KernActs, "Loading boot module '{}'", app.name());
        load_mod_async(&mut loader, app)?
    };

    let act = loader.0;
    let mut env_off = size_of::<env::BaseEnv>();
    let argv_addr = write_arguments(&["root"], act.tile_id(), env_phys, &mut env_off);
    let envp_addr = write_arguments(&env::vars_raw(), act.tile_id(), env_phys, &mut env_off);

    // write env to target tile
    let senv = env::BaseEnv {
        boot: env::BootEnv {
            platform: env::boot().platform,
            argc: 1,
            argv: argv_addr as u64,
            envp: envp_addr as u64,
            tile_id: act.tile_id().raw() as u64,
            tile_desc: act.tile_desc().value(),
            raw_tile_count: env::boot().raw_tile_count,
            raw_tile_ids: env::boot().raw_tile_ids,
            ..Default::default()
        },
        sp: act.tile_desc().stack_top() as u64,
        entry: entry as u64,
        act_id: act.id() as u64,
        heap_size: MOD_HEAP_SIZE as u64,
        rmng_sel: kif::INVALID_SEL,
        first_sel: act.first_sel(),
        first_std_ep: act.eps_start() as u64,
        ..Default::default()
    };
    ktcu::write_slice(act.tile_id(), env_phys, &[senv]);

    Ok(())
}

fn get_mod(name: &str) -> Option<&kif::boot::Mod> {
    for m in platform::mods() {
        if let Some(bin_name) = m.name().split(' ').next() {
            if bin_name == name {
                return Some(m);
            }
        }
    }

    None
}

fn read_from_mod<T: Default>(bm: &kif::boot::Mod, off: goff) -> Result<T, Error> {
    if off + size_of::<T>() as goff > bm.size {
        return Err(Error::new(Code::InvalidElf));
    }

    let gaddr = GlobAddr::new(bm.addr);
    Ok(ktcu::read_obj(gaddr.tile(), gaddr.offset() + off))
}

fn load_mod_async<L>(loader: &mut L, bm: &kif::boot::Mod) -> Result<usize, Error>
where
    L: ELFLoader,
{
    let mod_addr = GlobAddr::new(bm.addr);
    let hdr: elf::ElfHeader = read_from_mod(bm, 0)?;

    if hdr.ident[0] != b'\x7F'
        || hdr.ident[1] != b'E'
        || hdr.ident[2] != b'L'
        || hdr.ident[3] != b'F'
    {
        return Err(Error::new(Code::InvalidElf));
    }

    // copy load segments to destination tile
    let mut end = 0;
    let mut off = hdr.ph_off;
    for _ in 0..hdr.ph_num {
        // load program header
        let phdr: elf::ProgramHeader = read_from_mod(bm, off as goff)?;
        off += hdr.ph_entry_size as usize;

        // we're only interested in non-empty load segments
        if phdr.ty != elf::PHType::Load.into() || phdr.mem_size == 0 {
            continue;
        }

        let flags = PageFlags::from(kif::Perm::from(elf::PHFlags::from_bits_truncate(
            phdr.flags,
        )));
        let offset = math::round_dn(phdr.offset as usize, PAGE_SIZE);
        let virt = math::round_dn(phdr.virt_addr, PAGE_SIZE);

        // bss?
        if phdr.file_size == 0 {
            let size = math::round_up(
                (phdr.virt_addr & PAGE_MASK) + phdr.mem_size as usize,
                PAGE_SIZE,
            );

            loader.zero_segment_async(virt as goff, size, flags)?;
            end = virt + size;
        }
        else {
            assert!(phdr.mem_size == phdr.file_size);
            let size = (phdr.offset as usize & PAGE_MASK) + phdr.file_size as usize;
            loader.load_segment_async(
                virt as goff,
                mod_addr + offset as goff,
                size,
                flags,
                true,
            )?;
            end = virt + size;
        }
    }

    // map heap and stack
    let end = math::round_up(end, PAGE_SIZE);
    loader.map_heap_async(end as goff)?;
    loader.map_stack_async()?;

    Ok(hdr.entry)
}

struct MetalELFLoader {
    dst: GlobAddr,
    offset: goff,
}

impl MetalELFLoader {
    fn new(dst: GlobAddr, offset: goff) -> Self {
        Self { dst, offset }
    }
}

impl ELFLoader for MetalELFLoader {
    #[allow(m3_async::no_async_call)]
    fn load_segment_async(
        &mut self,
        virt: goff,
        phys: GlobAddr,
        size: usize,
        _flags: PageFlags,
        _map: bool,
    ) -> Result<(), Error> {
        ktcu::copy(
            // destination
            self.dst.tile(),
            self.dst.offset() + virt as goff - self.offset,
            // source
            phys.tile(),
            phys.offset(),
            size,
        )
    }

    #[allow(m3_async::no_async_call)]
    fn zero_segment_async(
        &mut self,
        virt: goff,
        size: usize,
        _flags: PageFlags,
    ) -> Result<(), Error> {
        ktcu::clear(
            self.dst.tile(),
            self.dst.offset() + virt - self.offset,
            size,
        )
    }
}

struct ActivityELFLoader<'a>(&'a Activity);

impl ELFLoader for ActivityELFLoader<'_> {
    fn load_segment_async(
        &mut self,
        virt: goff,
        phys: GlobAddr,
        size: usize,
        flags: PageFlags,
        map: bool,
    ) -> Result<(), Error> {
        if self.0.tile_desc().has_virtmem() {
            let dst_sel = virt >> PAGE_BITS;
            let pages = math::round_up(size, PAGE_SIZE) >> PAGE_BITS;

            let phys_align = GlobAddr::new_with(phys.tile(), phys.offset() & !PAGE_MASK as goff);
            let map_obj = MapObject::new(phys_align, flags);
            if map {
                map_obj.map_async(self.0, virt & !PAGE_MASK as goff, phys_align, pages, flags)?;
            }

            self.0.map_caps().borrow_mut().insert(Capability::new_range(
                SelRange::new_range(dst_sel as kif::CapSel, pages as kif::CapSel),
                KObject::Map(map_obj),
            ))
        }
        else {
            MetalELFLoader::new(GlobAddr::new_with(self.0.tile_id(), 0), 0)
                .load_segment_async(virt, phys, size, flags, map)
        }
    }

    fn zero_segment_async(
        &mut self,
        virt: goff,
        size: usize,
        flags: PageFlags,
    ) -> Result<(), Error> {
        let phys = if self.0.tile_desc().has_virtmem() {
            let mem =
                mem::borrow_mut().allocate(mem::MemType::ROOT, size as goff, PAGE_SIZE as goff)?;
            self.load_segment_async(virt as goff, mem.global(), size, flags, true)?;

            ktcu::glob_to_phys_remote(self.0.tile_id(), mem.global(), flags)?
        }
        else {
            virt
        };

        MetalELFLoader::new(GlobAddr::new_with(self.0.tile_id(), 0), 0)
            .zero_segment_async(phys, size, flags)
    }

    fn map_heap_async(&mut self, virt: goff) -> Result<(), Error> {
        if self.0.tile_desc().has_virtmem() {
            let phys = mem::borrow_mut().allocate(
                mem::MemType::ROOT,
                MOD_HEAP_SIZE as goff,
                PAGE_SIZE as goff,
            )?;
            self.load_segment_async(virt, phys.global(), MOD_HEAP_SIZE, PageFlags::RW, true)
        }
        else {
            Ok(())
        }
    }

    fn map_stack_async(&mut self) -> Result<(), Error> {
        if self.0.tile_desc().has_virtmem() {
            let (virt, size) = self.0.tile_desc().stack_space();
            let phys =
                mem::borrow_mut().allocate(mem::MemType::ROOT, size as goff, PAGE_SIZE as goff)?;
            self.load_segment_async(virt as goff, phys.global(), size, PageFlags::RW, true)
        }
        else {
            Ok(())
        }
    }
}

fn write_arguments<S>(args: &[S], tile: tcu::TileId, env_phys: goff, env_off: &mut usize) -> usize
where
    S: AsRef<str>,
{
    let (arg_buf, arg_ptr, arg_end) = env::collect_args(args, *env_off + ENV_START);

    // write actual arguments to memory
    ktcu::write_mem(
        tile,
        env_phys + *env_off as goff,
        arg_buf.as_ptr() as *const u8,
        arg_buf.len(),
    );

    // write argument pointers to memory
    let arg_ptr_off = math::round_up(arg_end - ENV_START, size_of::<u64>());
    ktcu::write_mem(
        tile,
        env_phys + arg_ptr_off as goff,
        arg_ptr.as_ptr() as *const _,
        arg_ptr.len() * size_of::<u64>(),
    );

    *env_off = arg_ptr_off + arg_ptr.len() * size_of::<u64>();
    ENV_START + arg_ptr_off
}
