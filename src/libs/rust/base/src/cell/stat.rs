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

use core::cell::Cell;
use core::fmt;

/// A cell that can be used as a static object in single threaded environments
///
/// Since M3 does not support multiple threads within one address space, a static cell is fine.
pub struct StaticCell<T: Copy + Sized> {
    inner: Cell<T>,
}

unsafe impl<T: Copy + Sized> Sync for StaticCell<T> {
}

impl<T: Copy + Sized> StaticCell<T> {
    /// Creates a new static cell with given value
    pub const fn new(val: T) -> Self {
        StaticCell {
            inner: Cell::new(val),
        }
    }

    /// Returns the inner value
    pub fn get(&self) -> T {
        self.inner.get()
    }

    /// Sets the inner value to `val`
    pub fn set(&self, val: T) {
        self.inner.set(val);
    }

    /// Sets the inner value to `val` and returns the old value
    pub fn replace(&self, val: T) -> T {
        self.inner.replace(val)
    }

    /// Returns a mutable pointer to the inner value
    pub fn as_ptr(&self) -> *mut T {
        self.inner.as_ptr()
    }
}

impl<T: Copy + fmt::Debug> fmt::Debug for StaticCell<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(f)
    }
}
