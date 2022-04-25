/*
 * Copyright (C) 2022 Nils Asmussen, Barkhausen Institut
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

use core::ops::Deref;

use crate::col::String;

pub enum StringRef<'s> {
    Borrowed(&'s str),
    Owned(String),
}

impl<'s> StringRef<'s> {
    pub fn set(&mut self, val: String) {
        *self = Self::Owned(val);
    }
}

impl<'s> Deref for StringRef<'s> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(r) => *r,
            Self::Owned(s) => s,
        }
    }
}
