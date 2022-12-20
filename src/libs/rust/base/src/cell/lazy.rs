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

use crate::cell::{Ref, RefMut, StaticCell, StaticRefCell, UnsafeCell};
use crate::mem;

/// A `LazyStaticCell` is the same as the [`StaticCell`](super::StaticCell), but contains an
/// [`Option<T>`](Option). At construction, the value is `None` and it needs to be set before other
/// functions can be used. That is, all access functions assume that the value has been set before.
pub struct LazyStaticCell<T: Copy + Sized> {
    inner: StaticCell<Option<T>>,
}

impl<T: Copy> LazyStaticCell<T> {
    pub const fn default() -> Self {
        Self {
            inner: StaticCell::new(None),
        }
    }

    /// Returns true if the value has been set
    pub fn is_some(&self) -> bool {
        self.inner.get().is_some()
    }

    /// Returns the inner value
    pub fn get(&self) -> T {
        self.inner.get().unwrap()
    }

    /// Sets the inner value to `val` and returns the old value
    pub fn set(&self, val: T) -> Option<T> {
        self.inner.replace(Some(val))
    }

    /// Removes the inner value and returns the old value
    pub fn unset(&self) -> Option<T> {
        self.inner.replace(None)
    }
}

/// A `LazyStaticRefCell` is the same as the [`StaticRefCell`](super::StaticRefCell), but contains an
/// [`Option<T>`](Option). At construction, the value is `None` and it needs to be set before other
/// functions can be used. That is, all access functions assume that the value has been set before.
/// A cell that allows to mutate a static immutable object in single threaded environments.
pub struct LazyStaticRefCell<T: Sized> {
    inner: StaticRefCell<Option<T>>,
}

unsafe impl<T: Sized> Sync for LazyStaticRefCell<T> {
}

impl<T: Sized> LazyStaticRefCell<T> {
    /// Creates a new static cell with given value
    pub const fn default() -> Self {
        Self {
            inner: StaticRefCell::new(None),
        }
    }

    /// Returns true if the value has been set
    pub fn is_some(&self) -> bool {
        self.inner.borrow().is_some()
    }

    /// Returns a reference to the inner value
    pub fn borrow(&self) -> Ref<'_, T> {
        Ref::map(self.inner.borrow(), |t| t.as_ref().unwrap())
    }

    /// Returns a reference-counted mutable reference to the inner value
    pub fn borrow_mut(&self) -> RefMut<'_, T> {
        RefMut::map(self.inner.borrow_mut(), |t| t.as_mut().unwrap())
    }

    /// Replaces the inner value with `val` and returns the old value
    pub fn set(&self, val: T) -> Option<T> {
        self.inner.replace(Some(val))
    }

    /// Removes the inner value and returns the old value
    pub fn unset(&self) -> Option<T> {
        self.inner.replace(None)
    }
}

/// A `LazyReadOnlyCell` is a cell that can be used for a static variable. It has to be initialized
/// (once) lazily and can afterwards only be read.
pub struct LazyReadOnlyCell<T: Sized> {
    inner: UnsafeCell<Option<T>>,
}

unsafe impl<T: Sized> Sync for LazyReadOnlyCell<T> {
}

impl<T: Sized> LazyReadOnlyCell<T> {
    /// Creates a new static cell with given value
    pub const fn default() -> Self {
        Self {
            inner: UnsafeCell::new(None),
        }
    }

    /// Returns true if the value has been set
    pub fn is_some(&self) -> bool {
        // safety: since we don't support multi-threading, checking whether it exists is okay
        unsafe { (*self.inner.get()).is_some() }
    }

    /// Returns a reference to the inner value
    pub fn get(&self) -> &T {
        // safety: since the value can only be set once and cannot be mutated afterwards, we can
        // hand out normal (immutable) references without runtime checks
        unsafe { (*self.inner.get()).as_ref().unwrap() }
    }

    /// Sets the inner value to `val`. Can only be called once.
    pub fn set(&self, val: T) {
        // safety: since the value can only be set once and cannot be used before it was set, nobody
        // can already have a reference to the value
        let old = unsafe { self.reset(val) };
        assert!(old.is_none());
    }

    /// Resets the inner value to `val` and returns the old value.
    ///
    /// # Safety
    ///
    /// The caller needs to make sure that there are no references left to the old value.
    pub unsafe fn reset(&self, val: T) -> Option<T> {
        mem::replace(&mut *self.inner.get(), Some(val))
    }
}
