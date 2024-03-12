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

//! Provides access to the program environment

use core::iter;

use derivative::Derivative;

use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::boxed::Box;
use crate::cell::LazyStaticRefCell;
use crate::cfg;
use crate::col::{String, ToString, Vec};
use crate::format;
use crate::kif::TileDesc;
use crate::mem::VirtAddr;
use crate::tcu::TileId;
use crate::util;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[repr(u64)]
pub enum Platform {
    #[default]
    Gem5,
    Hw,
}

#[derive(Copy, Clone, Derivative, Debug)]
#[derivative(Default)]
#[repr(C)]
pub struct BootEnv {
    pub platform: Platform,
    pub tile_id: u64,
    pub tile_desc: u64,
    pub argc: u64,
    pub argv: u64,
    pub envp: u64,
    pub kenv: u64,
    pub raw_tile_count: u64,
    #[derivative(Default(value = "[0u64; cfg::MAX_TILES * cfg::MAX_CHIPS]"))]
    pub raw_tile_ids: [u64; cfg::MAX_TILES * cfg::MAX_CHIPS],
}

impl BootEnv {
    pub fn tile_id(self) -> TileId {
        TileId::new_from_raw(self.tile_id as u16)
    }

    pub fn tile_desc(self) -> TileDesc {
        TileDesc::new_from(self.tile_desc)
    }
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct BaseEnv {
    pub boot: BootEnv,

    pub shared: u64,
    pub sp: u64,
    pub entry: u64,
    pub closure: u64,
    pub heap_size: u64,
    pub first_std_ep: u64,
    pub first_sel: u64,
    pub act_id: u64,

    pub rmng_sel: u64,
    pub pager_sess: u64,
    pub pager_sgate: u64,

    pub mounts_addr: u64,
    pub mounts_len: u64,

    pub fds_addr: u64,
    pub fds_len: u64,

    pub data_addr: u64,
    pub data_len: u64,
}

/// Collects the strings and pointers for the given slice of arguments to pass to a program.
///
/// The strings and pointers are stored relative to the given address (`addr`).
///
/// Returns a tuple of the strings, pointers, and the final address (for a another call of
/// `collect_args`).
pub fn collect_args<S>(args: &[S], addr: VirtAddr) -> (Vec<u8>, Vec<VirtAddr>, VirtAddr)
where
    S: AsRef<str>,
{
    let mut arg_ptr = Vec::<VirtAddr>::new();
    let mut arg_buf = Vec::new();

    let mut arg_addr = addr;
    for s in args {
        // push argv entry
        arg_ptr.push(arg_addr);

        // push string
        let arg = s.as_ref().as_bytes();
        arg_buf.extend_from_slice(arg);

        // 0-terminate it
        arg_buf.push(b'\0');

        arg_addr += arg.len() + 1;
    }
    arg_ptr.push(VirtAddr::null());

    (arg_buf, arg_ptr, arg_addr)
}

pub fn boot() -> &'static BootEnv {
    // safety: the cast is okay because we trust our loader to put the environment at that place
    unsafe { &*(cfg::ENV_START.as_ptr()) }
}

/// The closure used by `Activity::run`
pub struct Closure {
    func: Option<Box<dyn FnOnce() -> i32 + Send>>,
}

impl Closure {
    /// Creates a new object for given closure
    pub fn new<F>(func: Box<F>) -> Self
    where
        F: FnOnce() -> i32 + Send + 'static,
    {
        Closure { func: Some(func) }
    }

    /// Calls the closure (can only be done once) and returns its exit code
    pub fn call(&mut self) -> i32 {
        match self.func.take() {
            Some(c) => c(),
            None => 1,
        }
    }
}

/// The command line argument iterator
///
/// # Examples
///
/// ```
/// for arg in env::args() {
///     println!("{}", arg);
/// }
/// ```
#[derive(Copy, Clone)]
pub struct Args {
    pos: isize,
}

impl Args {
    fn arg(self, idx: isize) -> &'static str {
        // safety: we assume that our loader has put valid strings at argv
        unsafe {
            let args = boot().argv as *const u64;
            let arg = *args.offset(idx);
            util::cstr_to_str(arg as *const i8)
        }
    }

    /// Returns true if there are no arguments
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }

    /// Returns the number of arguments
    pub fn len(self) -> usize {
        boot().argc as usize
    }
}

impl iter::Iterator for Args {
    type Item = &'static str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos < boot().argc as isize {
            let arg = self.arg(self.pos);
            self.pos += 1;
            Some(arg)
        }
        else {
            None
        }
    }
}

/// Returns the argument iterator
pub fn args() -> Args {
    Args { pos: 0 }
}

/// The environment-variable iterator
///
/// # Examples
///
/// ```
/// for (key, val) in env::vars() {
///     println!("{}={}", key, val);
/// }
/// ```
#[derive(Default)]
pub struct Vars {
    pos: isize,
}

impl iter::Iterator for Vars {
    type Item = &'static str;

    fn next(&mut self) -> Option<Self::Item> {
        let args = boot().envp as *const u64;
        if args.is_null() {
            return None;
        }

        // safety: we assume that our loader has put valid pointers and strings in envp
        let arg = unsafe { *args.offset(self.pos) } as *const i8;
        if !arg.is_null() {
            unsafe {
                let var = util::cstr_to_str(arg);
                self.pos += 1;
                Some(var)
            }
        }
        else {
            None
        }
    }
}

static VARS: LazyStaticRefCell<Vec<String>> = LazyStaticRefCell::default();

// try to find the value from an iterator of strings of <key>=<value>
fn find_value<'s>(it: impl iter::Iterator<Item = &'s str>, key: &str) -> Option<&'s str> {
    it.map(|p| {
        let mut pair = p.splitn(2, '=');
        (pair.next().unwrap(), pair.next().unwrap())
    })
    .find(|(k, _v)| *k == key)
    .map(|(_k, v)| v)
}

/// Returns the value of the environment variable with given key.
pub fn var<K: AsRef<str>>(key: K) -> Option<String> {
    // if we have already copied the env vars, use the copy
    if VARS.is_some() {
        find_value(VARS.borrow().iter().map(|s| &s[..]), key.as_ref()).map(|v| v.to_string())
    }
    else {
        find_value(Vars::default(), key.as_ref()).map(|v| v.to_string())
    }
}

/// Returns the original (static) value of the environment variable with given key.
/// Variables removed or modified at runtime are not considered.
pub fn boot_var<K: AsRef<str>>(key: K) -> Option<&'static str> {
    find_value(Vars::default(), key.as_ref())
}

/// Returns the environment-variable iterator, containing each variable as a pair of key and value.
pub fn vars() -> Vec<(String, String)> {
    // split string into pair of key and value
    fn to_pair<S: AsRef<str>>(p: S) -> (String, String) {
        let mut pair = p.as_ref().splitn(2, '=');
        (
            pair.next().unwrap().to_string(),
            pair.next().unwrap().to_string(),
        )
    }

    // if we have already copied the env vars, use the copy
    if VARS.is_some() {
        VARS.borrow().iter().map(to_pair).collect()
    }
    else {
        Vars::default().map(to_pair).collect()
    }
}

/// Returns the environment-variable iterator, containing each variable as a single string in the
/// form of `key`=`value`.
pub fn vars_raw() -> Vec<String> {
    if VARS.is_some() {
        VARS.borrow().iter().map(|p| p.to_string()).collect()
    }
    else {
        Vars::default().map(|p| p.to_string()).collect()
    }
}

/// Sets the environment variable with given key to given value.
pub fn set_var<K: AsRef<str>, V: AsRef<str>>(key: K, val: V) {
    assert!(!key.as_ref().contains('='));

    // adding/changing a variable always requires a copy
    if !VARS.is_some() {
        VARS.set(Vars::default().map(|s| s.to_string()).collect());
    }

    // therefore we can forget about `Vars::new()` here.
    let mut var_vec = VARS.borrow_mut();
    // is there a variable with that name (string starts with key and the '=' follows directly)?
    if let Some(pair) = var_vec.iter_mut().find(|p| {
        p.starts_with(key.as_ref())
            && p.chars().position(|c| c == '=').unwrap() == key.as_ref().len()
    }) {
        // then just change the value
        *pair = format!("{}={}", key.as_ref(), val.as_ref());
    }
    else {
        var_vec.push(format!("{}={}", key.as_ref(), val.as_ref()));
    }
}

/// Removes the environment variable with given key.
pub fn remove_var<K: AsRef<str>>(key: K) {
    assert!(!key.as_ref().contains('='));

    // removing a variable always requires a copy
    if !VARS.is_some() {
        VARS.set(Vars::default().map(|s| s.to_string()).collect());
    }

    let mut var_vec = VARS.borrow_mut();
    // keep all variables with different keys
    var_vec.retain(|p| {
        !p.starts_with(key.as_ref())
            || p.chars().position(|c| c == '=').unwrap() != key.as_ref().len()
    });
}
