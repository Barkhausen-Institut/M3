/*
 * Copyright (C) 2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
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

//! Contains the abstraction for child activities

use core::cmp;
use core::fmt;
use core::ops::{Deref, DerefMut};

use base::kif::syscalls::MuxType;

use crate::cap::{CapFlags, Capability, SelSpace, Selector};
use crate::cell::Cell;
use crate::cfg;
use crate::client::{Pager, ResMngChild};
use crate::col::{String, ToString, Vec};
use crate::com::SendCap;
use crate::env::{self, Env};
use crate::errors::Error;
use crate::kif::{self, CapRngDesc, CapType};
use crate::mem::{self, GlobOff, VirtAddr};
use crate::rc::Rc;
use crate::serialize::{M3Serializer, VecSink};
use crate::syscalls;
use crate::tiles::{
    loader, Activity, DefaultMapper, KMem, Mapper, RunningActivity, RunningDeviceActivity,
    RunningProgramActivity, Tile,
};
use crate::vfs::{BufReader, Fd, File, FileRef, OpenFlags, VFS};

/// Represents a child activity
///
/// Child activities allow to execute code on the same or other tiles or make use of acceleratores
/// in other tiles. Creating a child activity only makes it known to the M³ kernel and potentially
/// the TileMux instance on the tile, but does not start it yet. This allows to customize the
/// environment and available resources for the child before its execution.
///
/// There are different types of items that can be transferred to childs:
/// - data (see [`ChildActivity::data_sink`])
/// - capabilities (see [`ChildActivity::delegate`])
/// - files (see [`ChildActivity::add_file`])
/// - mount points (see [`ChildActivity::add_mount`])
///
/// Finally, child activities are started with either:
/// - [`ChildActivity::start`] to run on a non-programmable accelerator
/// - [`ChildActivity::run`] to execute a function of our program in the child activity
/// - [`ChildActivity::exec`] to execute a given executable in the child activity
///
/// All three variants consume [`ChildActivity`] and yield a [`RunningActivity`] that holds the
/// activity during its execution and allows to stop it forcefully or wait until its completion.
///
/// # Example
///
/// ```
/// let tile = Tile::get("compat|own").unwrap();
/// let act = ChildActivity::new_with(tile, ActivityArgs::new("test")).unwrap();
///
/// let act = act.run(|| {
///     println!("Hello World!");
///     Ok(())
/// }).unwrap();
///
/// act.wait().unwrap();
/// ```
pub struct ChildActivity {
    base: Activity,
    child_sel: Cell<Selector>,
    rmng: ResMngChild,
    files: Vec<(Fd, Fd)>,
    mounts: Vec<(String, String)>,
}

/// The arguments for [`ChildActivity`] creations.
pub struct ActivityArgs<'n> {
    name: &'n str,
    pager: Option<Pager>,
    kmem: Option<Rc<KMem>>,
    rmng: Option<SendCap>,
    first_sel: Selector,
}

impl<'n> ActivityArgs<'n> {
    /// Creates a new instance of `ActivityArgs` using default settings.
    pub fn new(name: &'n str) -> ActivityArgs<'n> {
        ActivityArgs {
            name,
            pager: None,
            kmem: None,
            rmng: None,
            first_sel: kif::FIRST_FREE_SEL,
        }
    }

    /// Sets the `SendCap` used to communicate with the resource manager to `rmng`. Otherwise and by
    /// default, the resource manager of the own activity will be cloned.
    pub fn resmng(mut self, rmng: SendCap) -> Self {
        self.rmng = Some(rmng);
        self
    }

    /// Sets the pager. By default, the own pager will be cloned.
    pub fn pager(mut self, pager: Pager) -> Self {
        self.pager = Some(pager);
        self
    }

    /// Sets the kernel memory to use for the activity. By default, the kernel memory of the own
    /// activity will be used.
    pub fn kmem(mut self, kmem: Rc<KMem>) -> Self {
        self.kmem = Some(kmem);
        self
    }

    /// Sets the first selector to be used by the child (kif::FIRST_FREE_SEL by default).
    pub fn first_sel(mut self, sel: Selector) -> Self {
        self.first_sel = sel;
        self
    }
}

impl ChildActivity {
    /// Creates a new [`ChildActivity`] on tile `tile` with given name and default settings.
    ///
    /// The given tile specifies the tile where the activity will execute and its resource share
    /// (CPU time etc.). The name is only specified for debugging purposes.
    pub fn new(tile: Rc<Tile>, name: &str) -> Result<Self, Error> {
        Self::new_with(tile, ActivityArgs::new(name))
    }

    /// Creates a new [`ChildActivity`] on tile `tile` with given arguments.
    ///
    /// The given tile specifies the tile where the activity will execute and its resource share
    /// (CPU time etc.).
    pub fn new_with(tile: Rc<Tile>, args: ActivityArgs<'_>) -> Result<Self, Error> {
        let sel = SelSpace::get().alloc_sels(3);

        // create child activity struct
        let mut act = ChildActivity {
            // use an invalid cap temporary until we set the actual SendCap
            rmng: ResMngChild::default(),
            base: Activity::new_act(
                Capability::new(sel, CapFlags::empty()),
                tile.clone(),
                args.kmem.unwrap_or_else(|| Activity::own().kmem().clone()),
            ),
            child_sel: Cell::from(args.first_sel),
            files: Vec::new(),
            mounts: Vec::new(),
        };

        // create activity
        let (id, eps_start) =
            syscalls::create_activity(sel, args.name, tile.sel(), act.kmem().sel())?;
        act.id = id;
        act.eps_start = eps_start;

        // determine and initialize pager
        act.pager = if act.tile_desc().has_virtmem() {
            let pager = if let Some(p) = args.pager {
                Some(p)
            }
            else if let Some(p) = Activity::own().pager() {
                Some(p.new_clone()?)
            }
            else {
                None
            };
            match pager {
                Some(mut pg) => {
                    pg.init(&act)?;
                    Some(pg)
                },
                None => None,
            }
        }
        else {
            None
        };

        act.child_sel
            .set(cmp::max(act.kmem().sel() + 1, act.child_sel.get()));

        // determine resource manager
        act.rmng = if let Some(rmng_scap) = args.rmng {
            act.delegate_obj(rmng_scap.sel())?;
            ResMngChild::new(rmng_scap)
        }
        else {
            let sgate_sel = act.child_sel.get();
            act.child_sel.set(sgate_sel + 1);

            Activity::own()
                .resmng()
                .unwrap()
                .clone(&mut act, sgate_sel, args.name)?
        };

        // ensure that the child's cap space is not further ahead than ours
        // TODO improve that
        SelSpace::get()
            .next
            .set(cmp::max(act.child_sel.get(), SelSpace::get().next.get()));

        Ok(act)
    }

    /// Returns the selector of the resource manager
    pub fn resmng_sel(&self) -> Selector {
        self.rmng.sel()
    }

    /// Returns the map of files (destination fd, source fd) that are going to be delegated to this
    /// child activity on [`run`](Activity::run) and [`exec`](Activity::exec).
    pub(crate) fn files(&self) -> &Vec<(Fd, Fd)> {
        &self.files
    }

    /// Returns the map of mounts (destination path, source path) that are going to be delegated to
    /// this child activity on [`run`](Activity::run) and [`exec`](Activity::exec).
    pub(crate) fn mounts(&self) -> &Vec<(String, String)> {
        &self.mounts
    }

    /// Installs file `our_fd` as `child_fd` in this child activity.
    ///
    /// Files that are added to child activities are automatically delegated to the child upon
    /// [`run`](ChildActivity::run) and [`exec`](ChildActivity::exec).
    pub fn add_file(&mut self, child_fd: Fd, our_fd: Fd) {
        if let Some(mapping) = self.files.iter_mut().find(|(c, _p)| *c == child_fd) {
            mapping.1 = our_fd;
        }
        else {
            self.files.push((child_fd, our_fd));
        }
    }

    /// Installs mount `our_path` as `child_path` in this child activity.
    ///
    /// Mounts that are added to child activities are automatically delegated to the child upon
    /// [`run`](ChildActivity::run) and [`exec`](ChildActivity::exec).
    pub fn add_mount(&mut self, child_path: &str, our_path: &str) {
        if let Some(mapping) = self.mounts.iter_mut().find(|(c, _p)| c == child_path) {
            mapping.1 = our_path.to_string();
        }
        else {
            self.mounts
                .push((child_path.to_string(), our_path.to_string()))
        }
    }

    /// Returns a sink for the activity-local data
    ///
    /// The sink overwrites the activity-local data and will be transmitted to the activity when calling
    /// [`run`](ChildActivity::run) and [`exec`](ChildActivity::exec).
    pub fn data_sink(&mut self) -> M3Serializer<VecSink<'_>> {
        M3Serializer::new(VecSink::new(&mut self.data))
    }

    /// Delegates the object capability with selector `sel` of [`Activity::own`](Activity::own) to
    /// `self`.
    pub fn delegate_obj(&self, sel: Selector) -> Result<(), Error> {
        self.delegate(CapRngDesc::new(CapType::Object, sel, 1))
    }

    /// Delegates the given capability range of [`Activity::own`](Activity::own) to `self`.
    pub fn delegate(&self, crd: CapRngDesc) -> Result<(), Error> {
        let start = crd.start();
        self.delegate_to(crd, start)
    }

    /// Delegates the given capability range of [`Activity::own`](Activity::own) to `self` using
    /// selectors `dst`..`dst`+`crd.count()`.
    pub fn delegate_to(&self, crd: CapRngDesc, dst: Selector) -> Result<(), Error> {
        syscalls::exchange(self.sel(), crd, dst, false)?;
        self.child_sel
            .set(cmp::max(self.child_sel.get(), dst + crd.count()));
        Ok(())
    }

    /// Obtains the object capability with selector `sel` from `self` to
    /// [`Activity::own`](Activity::own).
    pub fn obtain_obj(&self, sel: Selector) -> Result<Selector, Error> {
        self.obtain(CapRngDesc::new(CapType::Object, sel, 1))
    }

    /// Obtains the given capability range of `self` to [`Activity::own`](Activity::own).
    pub fn obtain(&self, crd: CapRngDesc) -> Result<Selector, Error> {
        let count = crd.count();
        let start = SelSpace::get().alloc_sels(count);
        self.obtain_to(crd, start).map(|_| start)
    }

    /// Obtains the given capability range of `self` to [`Activity::own`](Activity::own) using
    /// selectors `dst`..`dst`+`crd.count()`.
    pub fn obtain_to(&self, crd: CapRngDesc, dst: Selector) -> Result<(), Error> {
        let own = CapRngDesc::new(crd.cap_type(), dst, crd.count());
        syscalls::exchange(self.sel(), own, crd.start(), true)
    }

    /// Starts the activity without running any code on it. This is intended for non-programmable
    /// accelerators and devices that implement the TileMux protocol to get started, but don't
    /// execute any code.
    pub fn start(self) -> Result<RunningDeviceActivity, Error> {
        let act = RunningDeviceActivity::new(self);
        act.start().map(|_| act)
    }

    /// Executes the program of [`Activity::own`](Activity::own) (`argv[0]`) with this activity and
    /// calls the given function instead of main.
    ///
    /// This has a few requirements/limitations:
    /// 1. the current binary has to be stored in a file system
    /// 2. this file system needs to be mounted, such that `argv[0]` is the current binary
    ///
    /// The method returns the [`RunningProgramActivity`] on success that can be used to wait for
    /// the functions completeness or to stop it.
    pub fn run(self, func: fn() -> Result<(), Error>) -> Result<RunningProgramActivity, Error> {
        let args = crate::env::args().collect::<Vec<_>>();
        let func_addr = VirtAddr::from(func as *const ());

        match self.tile().mux_type()? {
            // if TileMux is running on that tile, we have control about the activity's virtual
            // address space and can thus load the program into the address space
            MuxType::TileMux => {
                let file = VFS::open(args[0], OpenFlags::RX | OpenFlags::NEW_SESS)?;
                let mut mapper = DefaultMapper::new(self.tile_desc().has_virtmem());
                self.do_exec_file(
                    Some((&mut mapper, file.into_generic())),
                    &args,
                    Some(func_addr),
                )
            },

            // otherwise (e.g., for M³Linux) we simply don't load the program. In case of M³Linux,
            // this happens afterwards on Linux by performing a fork and exec with the arguments
            // from the environment.
            _ => self.do_exec_file(None, &args, Some(func_addr)),
        }
    }

    /// Executes the given program and arguments with `self`.
    ///
    /// The method returns the [`RunningProgramActivity`] on success that can be used to wait for
    /// the program completeness or to stop it.
    pub fn exec<S: AsRef<str>>(self, args: &[S]) -> Result<RunningProgramActivity, Error> {
        match self.tile().mux_type()? {
            // same as for `run`
            MuxType::TileMux => {
                let file = VFS::open(args[0].as_ref(), OpenFlags::RX | OpenFlags::NEW_SESS)?;
                let mut mapper = DefaultMapper::new(self.tile_desc().has_virtmem());
                self.exec_file(Some((&mut mapper, file.into_generic())), args)
            },
            _ => self.exec_file(None, args),
        }
    }

    /// Executes the program given as a [`FileRef`] with `self`, using `mapper` to initiate the
    /// address space and `args` as the arguments.
    ///
    /// The file has to have its own file session and therefore needs to be opened with
    /// [`OpenFlags::NEW_SESS`].
    ///
    /// The method returns the [`RunningProgramActivity`] on success that can be used to wait for
    /// the program completeness or to stop it.
    pub fn exec_file<S: AsRef<str>>(
        self,
        program: Option<(&mut dyn Mapper, FileRef<dyn File>)>,
        args: &[S],
    ) -> Result<RunningProgramActivity, Error> {
        self.do_exec_file(program, args, None)
    }

    fn do_exec_file<S: AsRef<str>>(
        self,
        program: Option<(&mut dyn Mapper, FileRef<dyn File>)>,
        args: &[S],
        closure: Option<VirtAddr>,
    ) -> Result<RunningProgramActivity, Error> {
        self.obtain_files_and_mounts()?;

        let (file, entry) = if let Some((mapper, file)) = program {
            let mut file = BufReader::new(file);
            let entry = loader::load_program(&self, mapper, &mut file)?;
            (Some(file), entry)
        }
        else {
            (None, VirtAddr::null())
        };

        self.load_environment(args, closure, entry)?;

        let act = RunningProgramActivity::new(self, file);
        act.start().map(|_| act)
    }

    fn obtain_files_and_mounts(&self) -> Result<(), Error> {
        let fsel = Activity::own().files().delegate(self)?;
        let msel = Activity::own().mounts().delegate(self)?;
        self.child_sel.set(self.child_sel.get().max(msel.max(fsel)));
        Ok(())
    }

    fn load_environment<S: AsRef<str>>(
        &self,
        args: &[S],
        closure: Option<VirtAddr>,
        entry: VirtAddr,
    ) -> Result<(), Error> {
        let (env_start, env_size) = env::boot().tile_desc().env_space();
        let mem = self.get_mem(env_start, env_size as GlobOff, kif::Perm::RW)?;

        // build child environment
        let mut cenv = crate::env::Env::default();
        cenv.set_platform(crate::env::get().platform());
        cenv.set_sp(self.tile_desc().stack_top());
        cenv.set_entry(entry);
        cenv.set_first_std_ep(self.eps_start);
        cenv.set_rmng(self.resmng_sel());
        cenv.set_first_sel(self.child_sel.get());
        cenv.set_pedesc(self.tile_desc());
        cenv.set_activity_id(self.id());
        cenv.copy_tile_ids(crate::env::get().tile_ids());

        if let Some(addr) = closure {
            cenv.set_closure(addr);
        }

        if let Some(ref pg) = self.pager {
            cenv.set_pager(pg);
            cenv.set_heap_size(cfg::APP_HEAP_SIZE);
        }
        else {
            cenv.set_heap_size(cfg::MOD_HEAP_SIZE);
        }

        // write arguments and environment variables
        let mut addr = env_start + mem::size_of_val(&cenv);
        let env_off = env_start.as_goff();
        cenv.set_argc(args.len());
        cenv.set_argv(env::write_args(args, &mem, &mut addr, env_off)?);
        cenv.set_envp(env::write_args(
            &crate::env::vars_raw(),
            &mem,
            &mut addr,
            env_off,
        )?);

        // serialize files, mounts, and data and write them to the child's memory
        let write_words =
            |words: &[u64], addr: VirtAddr| mem.write(words, (addr - env_start).as_goff());
        self.serialize_files(write_words, &mut cenv, &mut addr)?;
        self.serialize_mounts(write_words, &mut cenv, &mut addr)?;
        self.serialize_data(write_words, &mut cenv, &mut addr)?;

        // write environment to tile
        mem.write_bytes(&cenv as *const _ as *const u8, mem::size_of_val(&cenv), 0)
    }

    fn serialize_files<F>(&self, write: F, env: &mut Env, addr: &mut VirtAddr) -> Result<(), Error>
    where
        F: Fn(&[u64], VirtAddr) -> Result<(), Error>,
    {
        let mut fds_vec = Vec::new();
        let mut fds = M3Serializer::new(VecSink::new(&mut fds_vec));
        Activity::own().files().serialize(&self.files, &mut fds);
        write(fds.words(), *addr)?;
        env.set_files(*addr, fds.size());
        *addr += fds.size();
        Ok(())
    }

    fn serialize_mounts<F>(&self, write: F, env: &mut Env, addr: &mut VirtAddr) -> Result<(), Error>
    where
        F: Fn(&[u64], VirtAddr) -> Result<(), Error>,
    {
        let mut mounts_vec = Vec::new();
        let mut mounts = M3Serializer::new(VecSink::new(&mut mounts_vec));
        Activity::own()
            .mounts()
            .serialize(&self.mounts, &mut mounts);
        write(mounts.words(), *addr)?;
        env.set_mounts(*addr, mounts.size());
        *addr += mounts.size();
        Ok(())
    }

    fn serialize_data<F>(&self, write: F, env: &mut Env, addr: &mut VirtAddr) -> Result<(), Error>
    where
        F: Fn(&[u64], VirtAddr) -> Result<(), Error>,
    {
        write(&self.data, *addr)?;
        env.set_data(*addr, self.data.len() * mem::size_of::<u64>());
        Ok(())
    }
}

impl Deref for ChildActivity {
    type Target = Activity;

    fn deref(&self) -> &<Self as Deref>::Target {
        &self.base
    }
}

impl DerefMut for ChildActivity {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.base
    }
}

impl fmt::Debug for ChildActivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "ChildActivity[sel: {}, tile: {:?}]",
            self.sel(),
            self.tile()
        )
    }
}
