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
use core::ops::FnOnce;

use crate::boxed::Box;
use crate::cell::LazyStaticRefCell;
use crate::cfg;
use crate::col::{String, ToString, Vec};
use crate::format;
use crate::mem;
use crate::util;

int_enum! {
    pub struct Platform : u64 {
        const GEM5 = 0;
        const HW = 1;
    }
}

#[derive(Default, Copy, Clone)]
#[repr(C)]
pub struct EnvData {
    // boot env
    pub platform: u64,
    pub tile_id: u64,
    pub tile_desc: u64,
    pub argc: u64,
    pub argv: u64,
    pub envp: u64,
    pub heap_size: u64,
    pub kenv: u64,
    pub closure: u64,

    // set by TileMux
    pub shared: u64,

    // m3 env
    pub sp: u64,
    pub entry: u64,
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

    // only used in C++
    pub _backend: u64,
}

pub fn data() -> &'static EnvData {
    // safety: the cast is okay because we trust our loader to put the environment at that place
    unsafe { &*(cfg::ENV_START as *const _) }
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
        match mem::replace(&mut self.func, None) {
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
            let args = data().argv as *const u64;
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
        data().argc as usize
    }
}

impl iter::Iterator for Args {
    type Item = &'static str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos < data().argc as isize {
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
        let args = data().envp as *const u64;
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

/// Returns the value of the environment variable with given key.
pub fn var<K: AsRef<str>>(key: K) -> Option<String> {
    // try to find the value from an iterator of strings of <key>=<value>
    fn find_value<'s>(it: impl iter::Iterator<Item = &'s str>, key: &str) -> Option<String> {
        it.map(|p| {
            let mut pair = p.splitn(2, '=');
            (pair.next().unwrap(), pair.next().unwrap())
        })
        .find(|(k, _v)| *k == key)
        .map(|(_k, v)| v.to_string())
    }

    // if we have already copied the env vars, use the copy
    if VARS.is_some() {
        find_value(VARS.borrow().iter().map(|s| &s[..]), key.as_ref())
    }
    else {
        find_value(Vars::default(), key.as_ref())
    }
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
/// form of <key>=<value>.
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
