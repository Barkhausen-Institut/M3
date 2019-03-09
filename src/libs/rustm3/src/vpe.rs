/*
 * Copyright (C) 2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
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

use arch;
use boxed::{Box, FnBox};
use cap::{CapFlags, Capability, Selector};
use cell::StaticCell;
use col::Vec;
use com::{EpMux, MemGate, SendGate};
use core::fmt;
use dtu::{EP_COUNT, FIRST_FREE_EP, EpId};
use env;
use errors::{Code, Error};
use goff;
use kif::{CapType, CapRngDesc, INVALID_SEL, PEDesc};
use kif;
use session::{ResMng, Pager};
use syscalls;
use util;
use io::Read;
use vfs::{BufReader, FileRef, OpenFlags, Seek, SeekMode, VFS};
use vfs::{FileTable, Map, MountTable};

pub struct VPEGroup {
    cap: Capability,
}

impl VPEGroup {
    pub fn new() -> Result<Self, Error> {
        let sel = VPE::cur().alloc_sel();

        syscalls::create_vpe_group(sel)?;
        Ok(VPEGroup {
            cap: Capability::new(sel, CapFlags::empty()),
        })
    }

    pub fn sel(&self) -> Selector {
        self.cap.sel()
    }
}

pub struct VPE {
    cap: Capability,
    pe: PEDesc,
    mem: MemGate,
    rmng: ResMng,
    next_sel: Selector,
    eps: u64,
    rbufs: arch::rbufs::RBufSpace,
    pager: Option<Pager>,
    files: FileTable,
    mounts: MountTable,
}

pub struct VPEArgs<'n, 'p> {
    name: &'n str,
    pager: Option<&'p str>,
    pe: PEDesc,
    muxable: bool,
    group: Option<VPEGroup>,
    rmng: Option<ResMng>,
}

pub trait Mapper {
    fn map_file<'l>(&mut self, pager: Option<&'l Pager>, file: &mut BufReader<FileRef>, foff: usize,
                    virt: goff, len: usize, perm: kif::Perm) -> Result<bool, Error>;
    fn map_anon<'l>(&mut self, pager: Option<&'l Pager>,
                    virt: goff, len: usize, perm: kif::Perm) -> Result<bool, Error>;

    fn init_mem(&self, buf: &mut [u8], mem: &MemGate,
                file: &mut BufReader<FileRef>, foff: usize, fsize: usize,
                virt: goff, memsize: usize) -> Result<(), Error> {
        file.seek(foff, SeekMode::SET)?;

        let mut count = fsize;
        let mut segoff = virt as usize;
        while count > 0 {
            let amount = util::min(count, buf.len());
            let amount = file.read(&mut buf[0..amount])?;

            mem.write(&buf[0..amount], segoff as goff)?;

            count -= amount;
            segoff += amount;
        }

        self.clear_mem(buf, mem, (memsize - fsize) as usize, segoff)
    }

    fn clear_mem(&self, buf: &mut [u8], mem: &MemGate,
                 mut count: usize, mut dst: usize) -> Result<(), Error> {
        if count == 0 {
            return Ok(())
        }

        for i in 0..buf.len() {
            buf[i] = 0;
        }

        while count > 0 {
            let amount = util::min(count, buf.len());
            mem.write(&buf[0..amount], dst as goff)?;
            count -= amount;
            dst += amount;
        }

        Ok(())
    }
}

pub struct DefaultMapper {
    has_virtmem: bool,
}

impl DefaultMapper {
    pub fn new(has_virtmem: bool) -> Self {
        DefaultMapper {
            has_virtmem: has_virtmem,
        }
    }
}

impl Mapper for DefaultMapper {
    fn map_file<'l>(&mut self, pager: Option<&'l Pager>, file: &mut BufReader<FileRef>, foff: usize,
                    virt: goff, len: usize, perm: kif::Perm) -> Result<bool, Error> {
        if let Some(pg) = pager {
            file.get_ref().map(pg, virt, foff, len, perm).map(|_| false)
        }
        else if self.has_virtmem {
            // TODO handle that case
            unimplemented!();
        }
        else {
            Ok(true)
        }
    }
    fn map_anon<'l>(&mut self, pager: Option<&'l Pager>,
                    virt: goff, len: usize, perm: kif::Perm) -> Result<bool, Error> {
        if let Some(pg) = pager {
            pg.map_anon(virt, len, perm).map(|_| false)
        }
        else if self.has_virtmem {
            // TODO handle that case
            unimplemented!();
        }
        else {
            Ok(true)
        }
    }
}

pub trait Activity {
    fn vpe(&self) -> &VPE;
    fn vpe_mut(&mut self) -> &mut VPE;

    fn start(&self) -> Result<(), Error> {
        syscalls::vpe_ctrl(self.vpe().sel(), kif::syscalls::VPEOp::START, 0).map(|_| ())
    }

    fn stop(&self) -> Result<(), Error> {
        syscalls::vpe_ctrl(self.vpe().sel(), kif::syscalls::VPEOp::STOP, 0).map(|_| ())
    }

    fn wait(&self) -> Result<i32, Error> {
        syscalls::vpe_wait(&[self.vpe().sel()], 0).map(|r| r.1)
    }

    fn wait_async(&self, event: u64) -> Result<i32, Error> {
        syscalls::vpe_wait(&[self.vpe().sel()], event).map(|r| r.1)
    }
}

pub struct ClosureActivity {
    vpe: VPE,
    _closure: env::Closure,
}

impl ClosureActivity {
    pub fn new(vpe: VPE, closure: env::Closure) -> ClosureActivity {
        ClosureActivity {
            vpe: vpe,
            _closure: closure,
        }
    }
}

impl Activity for ClosureActivity {
    fn vpe(&self) -> &VPE {
        &self.vpe
    }
    fn vpe_mut(&mut self) -> &mut VPE {
        &mut self.vpe
    }
}

impl Drop for ClosureActivity {
    fn drop(&mut self) {
        self.stop().ok();
        if let Some(ref mut pg) = self.vpe.pager {
            pg.deactivate();
        }
    }
}

pub struct ExecActivity {
    vpe: VPE,
    _file: BufReader<FileRef>,
}

impl ExecActivity {
    pub fn new(vpe: VPE, file: BufReader<FileRef>) -> ExecActivity {
        ExecActivity {
            vpe: vpe,
            _file: file,
        }
    }
}

impl Activity for ExecActivity {
    fn vpe(&self) -> &VPE {
        &self.vpe
    }
    fn vpe_mut(&mut self) -> &mut VPE {
        &mut self.vpe
    }
}

impl Drop for ExecActivity {
    fn drop(&mut self) {
        self.stop().ok();
        if let Some(ref mut pg) = self.vpe.pager {
            pg.deactivate();
        }
    }
}

impl<'n, 'p> VPEArgs<'n, 'p> {
    pub fn new(name: &'n str) -> VPEArgs<'n, 'p> {
        VPEArgs {
            name: name,
            pager: None,
            pe: VPE::cur().pe(),
            muxable: false,
            group: None,
            rmng: None,
        }
    }

    pub fn resmng(mut self, rmng: ResMng) -> Self {
        self.rmng = Some(rmng);
        self
    }

    pub fn pe(mut self, pe: PEDesc) -> Self {
        self.pe = pe;
        self
    }

    pub fn pager(mut self, pager: &'p str) -> Self {
        self.pager = Some(pager);
        self
    }

    pub fn muxable(mut self, muxable: bool) -> Self {
        self.muxable = muxable;
        self
    }

    pub fn group(mut self, group: VPEGroup) -> Self {
        self.group = Some(group);
        self
    }
}

const VMA_RBUF_SIZE: usize  = 64;

// 0 and 1 are reserved for VPE cap and mem cap; the rest are used for EP caps
pub(crate) const FIRST_EP_SEL: Selector    = 2;
pub(crate) const FIRST_FREE_SEL: Selector  = FIRST_EP_SEL + (EP_COUNT - FIRST_FREE_EP) as Selector;

static CUR: StaticCell<Option<VPE>> = StaticCell::new(None);

impl VPE {
    fn new_cur() -> Self {
        // currently, the bitmask limits us to 64 endpoints
        const_assert!(EP_COUNT < util::size_of::<u64>() * 8);

        VPE {
            cap: Capability::new(0, CapFlags::KEEP_CAP),
            pe: PEDesc::new_from(0),
            mem: MemGate::new_bind(1),
            rmng: ResMng::new(SendGate::new_bind(0)),    // invalid
            next_sel: FIRST_FREE_SEL,
            eps: 0,
            rbufs: arch::rbufs::RBufSpace::new(),
            pager: None,
            files: FileTable::default(),
            mounts: MountTable::default(),
        }
    }

    fn init(&mut self) {
        let env = arch::env::get();
        self.pe = env.pe_desc();
        self.next_sel = env.load_nextsel();
        self.rmng = env.load_rmng();
        self.eps = env.load_eps();
        self.rbufs = env.load_rbufs();
        self.pager = env.load_pager();
        // mounts first; files depend on mounts
        self.mounts = env.load_mounts();
        self.files = env.load_fds();
    }

    pub fn cur() -> &'static mut VPE {
        if arch::env::get().has_vpe() {
            arch::env::get().vpe()
        }
        else {
            CUR.get_mut().as_mut().unwrap()
        }
    }

    pub fn new(name: &str) -> Result<Self, Error> {
        Self::new_with(VPEArgs::new(name))
    }

    pub fn new_with(args: VPEArgs) -> Result<Self, Error> {
        let sels = VPE::cur().alloc_sels(FIRST_FREE_SEL);

        let mut vpe = VPE {
            cap: Capability::new(sels + 0, CapFlags::empty()),
            pe: args.pe,
            mem: MemGate::new_bind(sels + 1),
            rmng: if let Some(rmng) = args.rmng { rmng } else { VPE::cur().resmng().clone() },
            next_sel: FIRST_FREE_SEL,
            eps: 0,
            rbufs: arch::rbufs::RBufSpace::new(),
            pager: None,
            files: FileTable::default(),
            mounts: MountTable::default(),
        };

        let rbuf = if args.pe.has_mmu() {
            vpe.alloc_rbuf(VMA_RBUF_SIZE)?
        }
        else {
            0
        };

        let pager = if args.pe.has_virtmem() {
            if let Some(p) = args.pager {
                Some(Pager::new(&mut vpe, rbuf, p)?)
            }
            else if let Some(p) = Self::cur().pager() {
                Some(p.new_clone(&mut vpe, rbuf)?)
            }
            else {
                None
            }
        }
        else {
            None
        };

        let crd = CapRngDesc::new(CapType::OBJECT, vpe.sel(), FIRST_FREE_SEL);
        vpe.pager = if let Some(mut pg) = pager {
            let sgate_sel = pg.child_sgate().sel();

            // now create VPE, which implicitly obtains the gate cap from us
            vpe.pe = syscalls::create_vpe(
                crd, sgate_sel, args.name,
                args.pe, pg.sep(), pg.rep(), args.muxable,
                args.group.map_or(INVALID_SEL, |g| g.sel())
            )?;

            // after the VPE creation, we can activate the receive gate
            // note that we do that here in case neither run nor exec is used
            pg.activate(vpe.ep_sel(FIRST_FREE_EP))?;

            // mark the pager caps allocated
            vpe.next_sel = util::max(sgate_sel + 1, vpe.next_sel);
            // now delegate our VPE cap and memory cap to the pager
            pg.delegate_caps(&vpe)?;
            // and delegate the pager cap to the VPE
            vpe.delegate_obj(pg.sel())?;
            Some(pg)
        }
        else {
            vpe.pe = syscalls::create_vpe(
                crd, INVALID_SEL, args.name,
                args.pe, 0, 0, args.muxable,
                args.group.map_or(INVALID_SEL, |g| g.sel())
            )?;
            None
        };

        if vpe.rmng.valid() {
            let rmng_sel = vpe.rmng.sel();
            vpe.delegate_obj(rmng_sel)?;
        }

        Ok(vpe)
    }

    pub fn sel(&self) -> Selector {
        self.cap.sel()
    }
    pub fn pe(&self) -> PEDesc {
        self.pe
    }
    pub fn pe_id(&self) -> u64 {
        arch::env::get().pe_id()
    }
    pub fn mem(&self) -> &MemGate {
        &self.mem
    }
    pub fn ep_sel(&self, ep: EpId) -> Selector {
        self.sel() + FIRST_EP_SEL + (ep - FIRST_FREE_EP) as Selector
    }

    pub(crate) fn rbufs(&mut self) -> &mut arch::rbufs::RBufSpace {
        &mut self.rbufs
    }

    pub fn files(&mut self) -> &mut FileTable {
        &mut self.files
    }
    pub fn mounts(&mut self) -> &mut MountTable {
        &mut self.mounts
    }

    pub fn resmng(&self) -> &ResMng {
        &self.rmng
    }
    pub fn pager(&self) -> Option<&Pager> {
        self.pager.as_ref()
    }

    pub fn alloc_sel(&mut self) -> Selector {
        self.alloc_sels(1)
    }
    pub fn alloc_sels(&mut self, count: u32) -> Selector {
        self.next_sel += count;
        self.next_sel - count
    }

    pub fn alloc_ep(&mut self) -> Result<EpId, Error> {
        for ep in FIRST_FREE_EP..EP_COUNT {
            if self.is_ep_free(ep) {
                self.eps |= 1 << ep;

                // invalidate the EP if necessary
                if self.sel() == 0 {
                    EpMux::get().reserve(ep);
                }

                return Ok(ep)
            }
        }
        Err(Error::new(Code::NoSpace))
    }

    pub fn is_ep_free(&self, ep: EpId) -> bool {
        ep >= FIRST_FREE_EP && (self.eps & (1 << ep)) == 0
    }

    pub fn free_ep(&mut self, ep: EpId) {
        self.eps &= !(1 << ep);
    }

    pub fn alloc_rbuf(&mut self, size: usize) -> Result<usize, Error> {
        self.rbufs.alloc(&self.pe, size)
    }
    pub fn free_rbuf(&mut self, addr: usize, size: usize) {
        self.rbufs.free(addr, size)
    }

    pub fn delegate_obj(&mut self, sel: Selector) -> Result<(), Error> {
        self.delegate(CapRngDesc::new(CapType::OBJECT, sel, 1))
    }
    pub fn delegate(&mut self, crd: CapRngDesc) -> Result<(), Error> {
        let start = crd.start();
        self.delegate_to(crd, start)
    }
    pub fn delegate_to(&mut self, crd: CapRngDesc, dst: Selector) -> Result<(), Error> {
        syscalls::exchange(self.sel(), crd, dst, false)?;
        self.next_sel = util::max(self.next_sel, dst + crd.count());
        Ok(())
    }

    pub fn obtain_obj(&mut self, sel: Selector) -> Result<Selector, Error> {
        self.obtain(CapRngDesc::new(CapType::OBJECT, sel, 1))
    }
    pub fn obtain(&mut self, crd: CapRngDesc) -> Result<Selector, Error> {
        let count = crd.count();
        let start = VPE::cur().alloc_sels(count);
        self.obtain_to(crd, start).map(|_| start)
    }

    pub fn obtain_to(&mut self, crd: CapRngDesc, dst: Selector) -> Result<(), Error> {
        let own = CapRngDesc::new(crd.cap_type(), dst, crd.count());
        syscalls::exchange(self.sel(), own, crd.start(), true)
    }

    pub fn revoke(&mut self, crd: CapRngDesc, del_only: bool) -> Result<(), Error> {
        syscalls::revoke(self.sel(), crd, !del_only)
    }

    pub fn obtain_fds(&mut self) -> Result<(), Error> {
        // TODO that's really bad. but how to improve that? :/
        let mut dels = Vec::new();
        self.files.collect_caps(self.sel(), &mut dels, &mut self.next_sel)?;
        for c in dels {
            self.delegate_obj(c)?;
        }
        Ok(())
    }
    pub fn obtain_mounts(&mut self) -> Result<(), Error> {
        let mut dels = Vec::new();
        self.mounts.collect_caps(self.sel(), &mut dels, &mut self.next_sel)?;
        for c in dels {
            self.delegate_obj(c)?;
        }
        Ok(())
    }

    #[cfg(target_os = "none")]
    pub fn run<F>(mut self, func: Box<F>) -> Result<ClosureActivity, Error>
                  where F: FnBox() -> i32, F: Send + 'static {
        use cfg;
        use cpu;
        use goff;

        let first_ep_sel = self.ep_sel(FIRST_FREE_EP);
        if let Some(ref mut pg) = self.pager {
            pg.activate(first_ep_sel)?;
        }

        let env = arch::env::get();
        let mut senv = arch::env::EnvData::default();

        let closure = {
            let mut mapper = DefaultMapper::new(self.pe.has_virtmem());
            let mut loader = arch::loader::Loader::new(
                self.pager.as_ref(), Self::cur().pager().is_some(), &mut mapper, &self.mem
            );

            // copy all regions to child
            senv.set_sp(cpu::get_sp());
            let entry = loader.copy_regions(senv.sp())?;
            senv.set_entry(entry);
            senv.set_heap_size(env.heap_size());
            senv.set_lambda(true);

            // store VPE address to reuse it in the child
            senv.set_vpe(&self);

            // env goes first
            let mut off = cfg::RT_START + util::size_of_val(&senv);

            // create and write closure
            let closure = env::Closure::new(func);
            self.mem.write_obj(&closure, off as goff)?;
            off += util::size_of_val(&closure);

            // write args
            senv.set_argc(env.argc());
            senv.set_argv(loader.write_arguments(&mut off, env::args())?);

            senv.set_pedesc(&self.pe());

            // write start env to PE
            self.mem.write_obj(&senv, cfg::RT_START as goff)?;

            closure
        };

        // go!
        let act = ClosureActivity::new(self, closure);
        act.start().map(|_| act)
    }

    #[cfg(target_os = "linux")]
    pub fn run<F>(self, func: Box<F>) -> Result<ClosureActivity, Error>
                  where F: FnBox() -> i32, F: Send + 'static {
        use libc;

        let mut closure = env::Closure::new(func);

        let mut chan = arch::loader::Channel::new()?;

        match unsafe { libc::fork() } {
            -1  => {
                Err(Error::new(Code::OutOfMem))
            },

            0   => {
                chan.wait();

                arch::env::reinit();
                arch::env::get().set_vpe(&self);
                ::io::reinit();
                self::reinit();
                ::com::reinit();
                arch::dtu::init();

                let res = closure.call();
                unsafe { libc::exit(res) };
            },

            pid => {
                // let the kernel create the config-file etc. for the given pid
                syscalls::vpe_ctrl(self.sel(), kif::syscalls::VPEOp::START, pid as u64).unwrap();

                chan.signal();

                Ok(ClosureActivity::new(self, closure))
            },
        }
    }

    pub fn exec<S: AsRef<str>>(self, args: &[S]) -> Result<ExecActivity, Error> {
        let file = VFS::open(args[0].as_ref(), OpenFlags::RX)?;
        let mut mapper = DefaultMapper::new(self.pe.has_virtmem());
        self.exec_file(&mut mapper, file, args)
    }

    #[cfg(target_os = "none")]
    #[allow(unused_mut)]
    pub fn exec_file<S: AsRef<str>>(mut self, mapper: &mut Mapper,
                                    mut file: FileRef, args: &[S]) -> Result<ExecActivity, Error> {
        use cfg;
        use goff;
        use serialize::Sink;
        use com::VecSink;

        let mut file = BufReader::new(file);

        let first_ep_sel = self.ep_sel(FIRST_FREE_EP);
        if let Some(ref mut pg) = self.pager {
            pg.activate(first_ep_sel)?;
        }

        let mut senv = arch::env::EnvData::default();

        {
            let mut loader = arch::loader::Loader::new(
                self.pager.as_ref(), Self::cur().pager().is_some(), mapper, &self.mem
            );

            // load program segments
            senv.set_sp(cfg::STACK_TOP);
            senv.set_entry(loader.load_program(&mut file)?);

            // write args
            let mut off = cfg::RT_START + util::size_of_val(&senv);
            senv.set_argc(args.len());
            senv.set_argv(loader.write_arguments(&mut off, args)?);

            // write file table
            {
                let mut fds = VecSink::new();
                self.files.serialize(&mut fds);
                self.mem.write(fds.words(), off as goff)?;
                senv.set_files(off, fds.size());
                off += fds.size();
            }

            // write mounts table
            {
                let mut mounts = VecSink::new();
                self.mounts.serialize(&mut mounts);
                self.mem.write(mounts.words(), off as goff)?;
                senv.set_mounts(off, mounts.size());
            }

            senv.set_rmng(self.rmng.sel());
            senv.set_rbufs(&self.rbufs);
            senv.set_next_sel(self.next_sel);
            senv.set_eps(self.eps);
            senv.set_pedesc(&self.pe());

            if let Some(ref pg) = self.pager {
                senv.set_pager(pg);
                senv.set_heap_size(cfg::APP_HEAP_SIZE);
            }
            else {
                senv.set_heap_size(cfg::MOD_HEAP_SIZE);
            }

            // write start env to PE
            self.mem.write_obj(&senv, cfg::RT_START as goff)?;
        }

        // go!
        let act = ExecActivity::new(self, file);
        act.start().map(|_| act)
    }

    #[cfg(target_os = "linux")]
    pub fn exec_file<S: AsRef<str>>(self, _mapper: &Mapper,
                                    mut file: FileRef, args: &[S]) -> Result<ExecActivity, Error> {
        use com::VecSink;
        use libc;
        use serialize::Sink;

        let path = arch::loader::copy_file(&mut file)?;

        let mut chan = arch::loader::Channel::new()?;

        match unsafe { libc::fork() } {
            -1  => {
                Err(Error::new(Code::OutOfMem))
            },

            0   => {
                chan.wait();

                let pid = unsafe { libc::getpid() };

                // write nextsel, eps, and rmng
                arch::loader::write_env_value(pid, "nextsel", self.next_sel as u64);
                arch::loader::write_env_value(pid, "eps", self.eps);
                arch::loader::write_env_value(pid, "rmng", self.rmng.sel() as u64);

                // write rbufs
                let mut rbufs = VecSink::new();
                rbufs.push(&self.rbufs.cur);
                rbufs.push(&self.rbufs.end);
                arch::loader::write_env_file(pid, "rbufs", rbufs.words(), rbufs.size());

                // write file table
                let mut fds = VecSink::new();
                self.files.serialize(&mut fds);
                arch::loader::write_env_file(pid, "fds", fds.words(), fds.size());

                // write mounts table
                let mut mounts = VecSink::new();
                self.mounts.serialize(&mut mounts);
                arch::loader::write_env_file(pid, "ms", mounts.words(), mounts.size());

                arch::loader::exec(args, &path);
            },

            pid => {
                // let the kernel create the config-file etc. for the given pid
                syscalls::vpe_ctrl(self.sel(), kif::syscalls::VPEOp::START, pid as u64).unwrap();

                chan.signal();

                Ok(ExecActivity::new(self, BufReader::new(file)))
            },
        }
    }
}

impl fmt::Debug for VPE {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "VPE[sel: {}, pe: {:?}]", self.sel(), self.pe())
    }
}

pub fn init() {
    CUR.set(Some(VPE::new_cur()));
    VPE::cur().init();
}

pub fn reinit() {
    VPE::cur().cap.set_flags(CapFlags::KEEP_CAP);
    VPE::cur().cap = Capability::new(0, CapFlags::KEEP_CAP);
    VPE::cur().mem = MemGate::new_bind(1);
}
