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

use crate::arch;
use crate::cap::{CapFlags, Capability, Selector};
use crate::cell::Cell;
use crate::col::{String, ToString, Vec};
use crate::env;
use crate::errors::Error;
use crate::kif;
use crate::kif::{CapRngDesc, CapType};
use crate::rc::Rc;
use crate::session::{Pager, ResMng};
use crate::syscalls;
use crate::tiles::{
    Activity, DefaultMapper, KMem, Mapper, RunningDeviceActivity, RunningProgramActivity,
    StateSerializer, Tile,
};
use crate::vfs::{BufReader, Fd, File, FileRef, OpenFlags, VFS};

/// Represents a child activity.
pub struct ChildActivity {
    base: Activity,
    child_sel: Cell<Selector>,
    files: Vec<(Fd, Fd)>,
    mounts: Vec<(String, String)>,
}

/// The arguments for [`ChildActivity`] creations.
pub struct ActivityArgs<'n> {
    name: &'n str,
    pager: Option<Pager>,
    kmem: Option<Rc<KMem>>,
    rmng: Option<ResMng>,
}

impl<'n> ActivityArgs<'n> {
    /// Creates a new instance of `ActivityArgs` using default settings.
    pub fn new(name: &'n str) -> ActivityArgs<'n> {
        ActivityArgs {
            name,
            pager: None,
            kmem: None,
            rmng: None,
        }
    }

    /// Sets the resource manager to `rmng`. Otherwise and by default, the resource manager of the
    /// own activity will be cloned.
    pub fn resmng(mut self, rmng: ResMng) -> Self {
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
}

impl ChildActivity {
    /// Creates a new [`ChildActivity`] on tile `tile` with given name and default settings. The
    /// activity provides access to the tile and allows to run an activity on the tile.
    pub fn new(tile: Rc<Tile>, name: &str) -> Result<Self, Error> {
        Self::new_with(tile, ActivityArgs::new(name))
    }

    /// Creates a new [`ChildActivity`] on tile `tile` with given arguments. The activity provides
    /// access to the tile and allows to run an activity on the tile.
    pub fn new_with(tile: Rc<Tile>, args: ActivityArgs<'_>) -> Result<Self, Error> {
        let sel = Activity::own().alloc_sels(3);

        let mut act = ChildActivity {
            base: Activity::new_act(
                Capability::new(sel, CapFlags::empty()),
                tile.clone(),
                args.kmem.unwrap_or_else(|| Activity::own().kmem().clone()),
            ),
            child_sel: Cell::from(kif::FIRST_FREE_SEL),
            files: Vec::new(),
            mounts: Vec::new(),
        };

        let pager = if act.tile_desc().has_virtmem() {
            if let Some(p) = args.pager {
                Some(p)
            }
            else if let Some(p) = Activity::own().pager() {
                Some(p.new_clone()?)
            }
            else {
                None
            }
        }
        else {
            None
        };

        act.pager = if let Some(mut pg) = pager {
            // now create activity, which implicitly obtains the gate cap from us
            let (id, eps_start) =
                syscalls::create_activity(sel, args.name, tile.sel(), act.kmem().sel())?;
            act.id = id;
            act.eps_start = eps_start;

            // delegate activity cap to pager
            pg.init(&act)?;
            Some(pg)
        }
        else {
            let (id, eps_start) =
                syscalls::create_activity(sel, args.name, tile.sel(), act.kmem().sel())?;
            act.id = id;
            act.eps_start = eps_start;
            None
        };
        act.child_sel
            .set(cmp::max(act.kmem().sel() + 1, act.child_sel.get()));

        // determine resource manager
        let resmng = if let Some(rmng) = args.rmng {
            act.delegate_obj(rmng.sel())?;
            rmng
        }
        else {
            let sgate_sel = act.child_sel.get();
            act.child_sel.set(sgate_sel + 1);

            Activity::own()
                .resmng()
                .unwrap()
                .clone(&mut act, sgate_sel, args.name)?
        };
        act.rmng = Some(resmng);
        // ensure that the child's cap space is not further ahead than ours
        // TODO improve that
        Activity::own().next_sel.set(cmp::max(
            act.child_sel.get(),
            Activity::own().next_sel.get(),
        ));

        Ok(act)
    }

    /// Returns the selector of the resource manager
    pub fn resmng_sel(&self) -> Option<Selector> {
        self.rmng.as_ref().map(|r| r.sel())
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
    pub fn data_sink(&mut self) -> StateSerializer<'_> {
        StateSerializer::new(&mut self.data)
    }

    /// Delegates the object capability with selector `sel` of [`Activity::own`](Activity::own) to
    /// `self`.
    pub fn delegate_obj(&self, sel: Selector) -> Result<(), Error> {
        self.delegate(CapRngDesc::new(CapType::OBJECT, sel, 1))
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
        self.obtain(CapRngDesc::new(CapType::OBJECT, sel, 1))
    }

    /// Obtains the given capability range of `self` to [`Activity::own`](Activity::own).
    pub fn obtain(&self, crd: CapRngDesc) -> Result<Selector, Error> {
        let count = crd.count();
        let start = Activity::own().alloc_sels(count);
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
        use crate::tiles::RunningActivity;

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
    pub fn run(self, func: fn() -> i32) -> Result<RunningProgramActivity, Error> {
        let args = env::args().collect::<Vec<_>>();
        let file = VFS::open(args[0], OpenFlags::RX | OpenFlags::NEW_SESS)?;
        let mut mapper = DefaultMapper::new(self.tile_desc().has_virtmem());

        let func_addr = func as *const () as usize;
        self.do_exec_file(Some((&mut mapper, file.into_generic())), &args, Some(func_addr))
    }

    /// Executes the given program and arguments with `self`.
    ///
    /// The method returns the [`RunningProgramActivity`] on success that can be used to wait for
    /// the program completeness or to stop it.
    pub fn exec<S: AsRef<str>>(self, args: &[S]) -> Result<RunningProgramActivity, Error> {
        let file = VFS::open(args[0].as_ref(), OpenFlags::RX | OpenFlags::NEW_SESS)?;
        let mut mapper = DefaultMapper::new(self.tile_desc().has_virtmem());
        self.exec_file(Some((&mut mapper, file.into_generic())), args)
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

    #[cfg(not(target_vendor = "host"))]
    #[allow(unused_mut)]
    fn do_exec_file<S: AsRef<str>>(
        mut self,
        program: Option<(&mut dyn Mapper, FileRef<dyn File>)>,
        args: &[S],
        closure: Option<usize>,
    ) -> Result<RunningProgramActivity, Error> {
        use crate::cfg;
        use crate::goff;
        use crate::mem;
        use crate::tiles::RunningActivity;

        self.obtain_files_and_mounts()?;

        let mut senv = arch::env::EnvData::default();

        let env_page_off = (cfg::ENV_START & !cfg::PAGE_MASK) as goff;
        let mem = self.get_mem(env_page_off, cfg::ENV_SIZE as goff, kif::Perm::RW)?;

        let (file, entry) = if let Some((mapper, mut file)) = program {
            let mut file = BufReader::new(file);
            let entry = arch::loader::load_program(&self, mapper, &mut file)?;
            (Some(file), entry)
        }
        else {
            (None, 0)
        };

        {
            // load program segments
            senv.set_platform(arch::env::get().platform());
            senv.set_sp(self.tile_desc().stack_top());
            senv.set_entry(entry);

            // write args
            let mut off = cfg::ENV_START + mem::size_of_val(&senv);
            senv.set_argc(args.len());
            senv.set_argv(arch::loader::write_arguments(&mem, &mut off, args)?);

            // write env vars
            senv.set_envp(arch::loader::write_arguments(
                &mem,
                &mut off,
                env::vars_raw(),
            )?);

            // write file table
            {
                let mut fds_vec = Vec::new();
                let mut fds = StateSerializer::new(&mut fds_vec);
                Activity::own().files().serialize(&self.files, &mut fds);
                let words = fds.words();
                mem.write_bytes(
                    words.as_ptr() as *const u8,
                    words.len() * mem::size_of::<u64>(),
                    off as goff - env_page_off,
                )?;
                senv.set_files(off, fds.size());
                off += fds.size();
            }

            // write mounts table
            {
                let mut mounts_vec = Vec::new();
                let mut mounts = StateSerializer::new(&mut mounts_vec);
                Activity::own()
                    .mounts()
                    .serialize(&self.mounts, &mut mounts);
                let words = mounts.words();
                mem.write_bytes(
                    words.as_ptr() as *const u8,
                    words.len() * mem::size_of::<u64>(),
                    off as goff - env_page_off,
                )?;
                senv.set_mounts(off, mounts.size());
                off += mounts.size();
            }

            // write data
            {
                let size = self.data.len() * mem::size_of::<u64>();
                mem.write_bytes(
                    self.data.as_ptr() as *const u8,
                    size,
                    off as goff - env_page_off,
                )?;
                senv.set_data(off, size);
            }

            // write closure
            if let Some(addr) = closure {
                senv.set_closure(addr);
            }

            senv.set_first_std_ep(self.eps_start);
            senv.set_rmng(self.resmng_sel().unwrap());
            senv.set_first_sel(self.child_sel.get());
            senv.set_pedesc(self.tile_desc());
            senv.set_activity_id(self.id());

            if let Some(ref pg) = self.pager {
                senv.set_pager(pg);
                senv.set_heap_size(cfg::APP_HEAP_SIZE);
            }
            else {
                senv.set_heap_size(cfg::MOD_HEAP_SIZE);
            }

            // write start env to tile
            mem.write_bytes(
                &senv as *const _ as *const u8,
                mem::size_of_val(&senv),
                cfg::ENV_START as goff - env_page_off,
            )?;
        }

        // go!
        let act = RunningProgramActivity::new(self, file);
        act.start().map(|_| act)
    }

    #[cfg(target_vendor = "host")]
    fn do_exec_file<S: AsRef<str>>(
        self,
        _mapper: &mut dyn Mapper,
        mut file: FileRef<dyn File>,
        args: &[S],
        closure: Option<usize>,
    ) -> Result<RunningProgramActivity, Error> {
        use crate::errors::Code;
        use crate::libc;

        self.obtain_files_and_mounts()?;

        let path = arch::loader::copy_file(&mut file)?;

        let mut p2c = arch::loader::Channel::new()?;
        let mut c2p = arch::loader::Channel::new()?;

        match unsafe { libc::fork() } {
            -1 => Err(Error::new(Code::OutOfMem)),

            0 => {
                // wait until the env file has been written by the kernel
                p2c.wait();

                let pid = unsafe { libc::getpid() };

                // tell child about fd to notify parent if TCU is ready
                arch::loader::write_env_values(pid, "tcurdy", &[c2p.fds()[1] as u64]);

                // write nextsel, eps, rmng, and kmem
                arch::loader::write_env_values(pid, "nextsel", &[self.child_sel.get()]);
                arch::loader::write_env_values(pid, "rmng", &[self.resmng_sel().unwrap()]);
                arch::loader::write_env_values(pid, "kmem", &[self.kmem.sel()]);

                // write closure
                if let Some(addr) = closure {
                    arch::loader::write_env_values(pid, "lambda", &[addr as u64]);
                }

                // write file table
                let mut fds_vec = Vec::new();
                let mut fds = StateSerializer::new(&mut fds_vec);
                Activity::own().files().serialize(&self.files, &mut fds);
                arch::loader::write_env_values(pid, "fds", fds.words());

                // write mounts table
                let mut mounts_vec = Vec::new();
                let mut mounts = StateSerializer::new(&mut mounts_vec);
                Activity::own()
                    .mounts()
                    .serialize(&self.mounts, &mut mounts);
                arch::loader::write_env_values(pid, "ms", mounts.words());

                // write env vars
                let mut vars_vec = Vec::new();
                let mut vars = StateSerializer::new(&mut vars_vec);
                for var in env::vars_raw() {
                    vars.push_str(&var);
                }
                arch::loader::write_env_values(pid, "vars", vars.words());

                // write data
                arch::loader::write_env_values(pid, "data", &self.data);

                arch::loader::exec(args, &path);
            },

            pid => {
                // let the kernel create the config-file etc. for the given pid
                syscalls::activity_ctrl(self.sel(), kif::syscalls::ActivityOp::START, pid as u64)
                    .unwrap();

                p2c.signal();
                // wait until the TCU sockets have been binded
                c2p.wait();

                Ok(RunningProgramActivity::new(self, BufReader::new(file)))
            },
        }
    }

    fn obtain_files_and_mounts(&self) -> Result<(), Error> {
        let fsel = Activity::own().files().delegate(self)?;
        let msel = Activity::own().mounts().delegate(self)?;
        self.child_sel.set(self.child_sel.get().max(msel.max(fsel)));
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
