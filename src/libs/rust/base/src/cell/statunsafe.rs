/*
 * Copyright (C) 2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019-2021 Nils Asmussen, Barkhausen Institut
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

use core::cell::UnsafeCell;

use crate::mem;

/// A cell that allows to mutate a static immutable object in single threaded environments
///
/// The get and set methods of this cell are unsafe, because the caller needs to ensure that Rusts
/// ownership rules are followed. That is, there can always just be either immutable references or
/// a single mutable reference to the inner object.
pub struct StaticUnsafeCell<T: Sized> {
    inner: UnsafeCell<T>,
}

unsafe impl<T: Sized> Sync for StaticUnsafeCell<T> {
}

impl<T: Sized> StaticUnsafeCell<T> {
    /// Creates a new static cell with given value
    pub const fn new(val: T) -> Self {
        StaticUnsafeCell {
            inner: UnsafeCell::new(val),
        }
    }

    /// Returns a reference to the inner value
    ///
    /// # Safety
    ///
    /// The caller needs to make sure that no mutable references exist (obtained via `get_mut`).
    pub unsafe fn get(&self) -> &T {
        &*self.inner.get()
    }

    /// Returns a mutable reference to the inner value
    ///
    /// # Safety
    ///
    /// The caller needs to make sure that no mutable references exist (obtained via `get_mut`).
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get_mut(&self) -> &mut T {
        &mut *self.inner.get()
    }

    /// Sets the inner value to `val` and returns the old value
    ///
    /// # Safety
    ///
    /// The caller needs to make sure that no mutable or immutable references exist (obtained via
    /// `get` and `get_mut`).
    pub unsafe fn set(&self, val: T) -> T {
        mem::replace(self.get_mut(), val)
    }
}

/// A `LazyStaticUnsafeCell` is the same as the [`StaticUnsafeCell`](super::StaticUnsafeCell), but
/// contains an [`Option<T>`](Option). At construction, the value is `None` and it needs to be set
/// before other functions can be used. That is, all access functions assume that the value has been
/// set before.
pub struct LazyStaticUnsafeCell<T: Sized> {
    inner: StaticUnsafeCell<Option<T>>,
}

impl<T> LazyStaticUnsafeCell<T> {
    pub const fn default() -> Self {
        Self {
            inner: StaticUnsafeCell::new(None),
        }
    }

    /// Returns true if the value has been set
    pub fn is_some(&self) -> bool {
        unsafe { self.inner.get() }.is_some()
    }

    /// Returns a reference to the inner value
    ///
    /// # Safety
    ///
    /// The caller needs to make sure that no mutable references exist (obtained via `get_mut`).
    pub unsafe fn get(&self) -> &T {
        self.inner.get().as_ref().unwrap()
    }

    /// Returns a mutable reference to the inner value
    ///
    /// # Safety
    ///
    /// The caller needs to make sure that no mutable references exist (obtained via `get_mut`).
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get_mut(&self) -> &mut T {
        self.inner.get_mut().as_mut().unwrap()
    }

    /// Sets the inner value to `val` and returns the old value
    ///
    /// # Safety
    ///
    /// The caller needs to make sure that no mutable or immutable references exist (obtained via
    /// `get` and `get_mut`).
    pub unsafe fn set(&self, val: T) -> Option<T> {
        self.inner.set(Some(val))
    }

    /// Removes the inner value and returns the old value
    ///
    /// # Safety
    ///
    /// The caller needs to make sure that no mutable or immutable references exist (obtained via
    /// `get` and `get_mut`).
    pub unsafe fn unset(&self) -> Option<T> {
        self.inner.set(None)
    }
}
