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

#![no_std]

mod loader;

use m3::boxed::Box;
use m3::cap::Selector;
use m3::cfg;
use m3::col::{ToString, Vec};
use m3::com::{GateCap, MemCap, MemGate, RGateArgs, RecvCap, RecvGate, SGateArgs, SendCap};
use m3::errors::{Code, Error, VerboseError};
use m3::format;
use m3::io::LogFlags;
use m3::kif;
use m3::kif::syscalls::MuxType;
use m3::log;
use m3::mem::{GlobAddr, GlobOff, VirtAddr};
use m3::syscalls;
use m3::tcu;
use m3::tiles::{Activity, ActivityArgs, ChildActivity};
use m3::util::math;
use m3::vfs::FileRef;

use resmng::childs::{self, Child, ChildManager, OwnChild};
use resmng::config;
use resmng::requests;
use resmng::resources::{memory, tiles, Resources};
use resmng::sendqueue;
use resmng::subsys;

struct RootChildStarter {
    bmods: Vec<kif::boot::Mod>,
    loaded_bmods: u64,
    pmp_bmods: u64,
}

impl RootChildStarter {
    fn new(bmods: Vec<kif::boot::Mod>) -> Self {
        Self {
            bmods,
            loaded_bmods: 0,
            pmp_bmods: 0,
        }
    }

    fn fetch_mod(&mut self, name: &str, pmp: bool) -> Option<(MemCap, GlobAddr, GlobOff)> {
        let RootChildStarter {
            bmods,
            loaded_bmods,
            pmp_bmods,
        } = self;

        let mask = if pmp { pmp_bmods } else { loaded_bmods };

        bmods
            .iter()
            .enumerate()
            .position(|(idx, m)| (*mask & (1 << idx)) == 0 && m.name() == name)
            .map(|idx| {
                *mask |= 1 << idx;
                (
                    subsys::Subsystem::get_mod(idx),
                    GlobAddr::new(bmods[idx].addr),
                    bmods[idx].size,
                )
            })
    }

    fn modules_range(
        &mut self,
        domain: &config::Domain,
    ) -> Result<(GlobAddr, GlobOff), VerboseError> {
        let mut start = GlobOff::MAX;
        let mut end = 0;

        for app in domain.apps() {
            let (_mgate, addr, size) = self.fetch_mod(app.name(), true).ok_or_else(|| {
                VerboseError::new(
                    Code::NotFound,
                    format!("Unable to find boot module {}", app.name()),
                )
            })?;

            start = start.min(addr.raw());
            end = end.max(addr.raw() + size);
        }

        Ok((GlobAddr::new(start), end - start))
    }
}

impl resmng::subsys::ChildStarter for RootChildStarter {
    fn get_bootmod(&mut self, name: &str) -> Result<MemGate, Error> {
        let idx = self
            .bmods
            .iter()
            .position(|m| m.name() == name)
            .ok_or_else(|| Error::new(Code::NotFound))?;
        subsys::Subsystem::get_mod(idx).activate()
    }

    fn start_async(
        &mut self,
        reqs: &requests::Requests,
        res: &mut Resources,
        child: &mut OwnChild,
    ) -> Result<(), VerboseError> {
        let tile = child.child_tile().tile_obj().clone();

        // if TileMux is running on that tile, we have control about the activity's virtual address
        // space and can thus load the program into the address space.
        let bmod = if tile.mux_type()? == MuxType::TileMux {
            Some(
                self.fetch_mod(child.cfg().name(), false)
                    .ok_or_else(|| Error::new(Code::NotFound))?,
            )
        }
        else {
            None
        };

        let resmng_scap = SendCap::new_with(
            SGateArgs::new(reqs.recv_gate())
                .credits(1)
                .label(tcu::Label::from(child.id())),
        )?;

        let mut act = ChildActivity::new_with(
            tile,
            ActivityArgs::new(child.name())
                .resmng(resmng_scap)
                .kmem(child.kmem()),
        )
        .map_err(|e| VerboseError::new(e.code(), "Unable to create Activity".to_string()))?;

        if Activity::own().mounts().get_by_path("/").is_some() {
            act.add_mount("/", "/");
        }

        let id = child.id();
        if let Some(sub) = child.subsys() {
            sub.finalize_async(res, id, &mut act)
                .expect("Unable to finalize subsystem");
        }

        let run = if let Some(bmod) = bmod {
            let mut bmapper = loader::BootMapper::new(
                act.sel(),
                bmod.0.sel(),
                act.tile_desc().has_virtmem(),
                child.mem().pool().clone(),
            );
            let bmod_gate = bmod.0.activate()?;
            let bfile = loader::BootFile::new(bmod_gate, bmod.2 as usize);
            let fd = Activity::own().files().add(Box::new(bfile))?;

            let run = act
                .exec_file(
                    Some((&mut bmapper, FileRef::new_owned(fd))),
                    child.arguments(),
                )
                .map_err(|e| {
                    VerboseError::new(
                        e.code(),
                        format!("Unable to execute boot module {}", child.name()),
                    )
                })?;

            for a in bmapper.fetch_allocs() {
                child.add_mem(a, None);
            }

            run
        }
        else {
            act.exec_file(None, child.arguments())
                .map_err(|e| VerboseError::new(e.code(), "Unable to start Activity".to_string()))?
        };

        child.set_running(Box::new(run));

        Ok(())
    }

    fn configure_tile(
        &mut self,
        res: &mut Resources,
        tile: &mut tiles::TileUsage,
        domain: &config::Domain,
    ) -> Result<(), VerboseError> {
        if tile.tile_obj().mux_type()? == MuxType::TileMux {
            if tile.tile_id() == Activity::own().tile_id() {
                // even for our own tile, we need to fetch the boot modules to ensure that we
                // assign the PMP regions for the other tiles correctly. For example, if we have
                // two net instances and one is co-located on our tile, we still need to fetch the
                // first module to give the second one (running on another tile) the correct PMP
                // region and not the one of the first module.
                let _range = self.modules_range(domain)?;
                return Ok(());
            }

            // determine minimum range of boot modules we need to give access to to cover all boot
            // modules that are run on this tile. note that these should always be contiguous,
            // because we collect the boot modules from the config.
            let range = self.modules_range(domain)?;
            let mslice = res.memory().find_mem(range.0, range.1, kif::Perm::RW)?;

            // create memory gate for this range
            let mgate = mslice.derive().map_err(|e| {
                VerboseError::new(e.code(), "Unable to derive from boot module".to_string())
            })?;

            // configure PMP EP
            tile.state_mut()
                .add_mem_region(mgate, range.1 as usize, true, true)
                .map_err(|e| {
                    VerboseError::new(
                        e.code(),
                        "Unable to add PMP region for boot module".to_string(),
                    )
                })
        }
        else {
            // for our own tile there is nothing to do, because we already have a PMP EP that covers
            // all boot modules
            Ok(())
        }
    }
}

fn create_rgate(
    buf_size: usize,
    msg_size: usize,
    rbuf_mem: Option<Selector>,
    rbuf_off: GlobOff,
    rbuf_addr: VirtAddr,
) -> Result<RecvGate, Error> {
    let rgate = RecvCap::new_with(
        RGateArgs::default()
            .order(math::next_log2(buf_size))
            .msg_order(math::next_log2(msg_size)),
    )?;
    rgate.activate_with(rbuf_mem, rbuf_off, rbuf_addr, None)
}

#[allow(clippy::vec_box)]
struct WorkloopArgs<'s, 'c, 'd, 'q, 'r> {
    starter: &'s mut RootChildStarter,
    childmng: &'c mut ChildManager,
    childs: &'d mut Vec<Box<OwnChild>>,
    reqs: &'q requests::Requests,
    res: &'r mut Resources,
}

fn workloop(args: &mut WorkloopArgs<'_, '_, '_, '_, '_>) {
    let WorkloopArgs {
        starter,
        childmng,
        childs,
        reqs,
        res,
    } = args;

    reqs.run_loop_async(childmng, childs, res, |_, _| {}, *starter)
        .expect("Running the workloop failed");
}

#[no_mangle]
pub fn main() -> Result<(), Error> {
    let (sub, mut res) = subsys::Subsystem::new().expect("Unable to read subsystem info");
    let args = sub.parse_args();
    for sem in &args.sems {
        res.semaphores_mut()
            .add_sem(sem.clone())
            .expect("Unable to add semaphore");
    }

    let max_msg_size = 1 << 8;
    let buf_size = max_msg_size * args.max_clients;

    // allocate and map memory for receive buffer. note that we need to do that manually here,
    // because RecvBufs allocate new physical memory via the resource manager and root does not have
    // a resource manager.
    let (rbuf_addr, _) = Activity::own().tile_desc().rbuf_space();
    let (rbuf_off, rbuf_mem) = if Activity::own().tile_desc().has_virtmem() {
        let buf_mem = res
            .memory_mut()
            .alloc_mem((buf_size + sendqueue::RBUF_SIZE) as GlobOff)
            .expect("Unable to allocate memory for receive buffers");
        let pages = (buf_mem.capacity() as usize + cfg::PAGE_SIZE - 1) / cfg::PAGE_SIZE;
        syscalls::create_map(
            rbuf_addr,
            Activity::own().sel(),
            buf_mem.sel(),
            0,
            pages as Selector,
            kif::Perm::R,
        )
        .expect("Unable to map receive buffers");
        (0, Some(buf_mem.sel()))
    }
    else {
        (rbuf_addr.as_goff(), None)
    };

    let req_rgate = create_rgate(buf_size, max_msg_size, rbuf_mem, rbuf_off, rbuf_addr)
        .expect("Unable to create request RecvGate");
    let reqs = requests::Requests::new(req_rgate);

    let squeue_rgate = create_rgate(
        sendqueue::RBUF_SIZE,
        sendqueue::RBUF_MSG_SIZE,
        rbuf_mem,
        rbuf_off + buf_size as GlobOff,
        rbuf_addr + buf_size,
    )
    .expect("Unable to create sendqueue RecvGate");
    sendqueue::init(squeue_rgate);

    let mut childmng = childs::ChildManager::default();

    let mut starter = RootChildStarter::new(sub.mods().clone());

    let mut childs = sub
        .create_childs(&mut childmng, &mut res, &mut starter)
        .expect("Unable to start subsystem");

    let mut wargs = WorkloopArgs {
        starter: &mut starter,
        childmng: &mut childmng,
        childs: &mut childs,
        reqs: &reqs,
        res: &mut res,
    };

    thread::init();
    for _ in 0..args.max_clients {
        thread::add_thread(
            VirtAddr::from(workloop as *const ()),
            &mut wargs as *mut _ as usize,
        );
    }

    wargs.childmng.start_waiting(1);

    workloop(&mut wargs);

    log!(LogFlags::Info, "All childs gone. Exiting.");

    Ok(())
}
