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

use core::cell::{Ref, RefCell, RefMut};
use core::fmt;

/// A cell that allows to mutate a static immutable object in single threaded environments.
///
/// The `StaticRefCell` uses `RefCell` internally to enforce the ownership rules at runtime.
pub struct StaticRefCell<T: Sized> {
    inner: RefCell<T>,
}

unsafe impl<T: Sized> Sync for StaticRefCell<T> {
}

impl<T: Sized> StaticRefCell<T> {
    /// Creates a new static cell with given value
    pub const fn new(val: T) -> Self {
        StaticRefCell {
            inner: RefCell::new(val),
        }
    }

    /// Returns a reference to the inner value
    pub fn borrow(&self) -> Ref<'_, T> {
        self.inner.borrow()
    }

    /// Returns a reference-counted mutable reference to the inner value
    pub fn borrow_mut(&self) -> RefMut<'_, T> {
        self.inner.borrow_mut()
    }

    /// Returns a mutable reference to the inner value
    ///
    /// # Safety
    ///
    /// The caller needs to make sure that there are no other immutable or mutable references
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get_mut_unsafe(&self) -> &mut T {
        &mut *self.inner.as_ptr()
    }

    /// Replaces the inner value with `val` and returns the old value
    pub fn replace(&self, val: T) -> T {
        self.inner.replace(val)
    }
}

impl<T: fmt::Debug> fmt::Debug for StaticRefCell<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.borrow().fmt(f)
    }
}
