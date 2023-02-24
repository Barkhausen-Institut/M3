/*
 * Copyright (C) 2021 Nils Asmussen, Barkhausen Institut
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

use core::fmt;

use crate::time::TimeDuration;

/// A generic duration of time
pub trait Duration: fmt::Debug + Sized {
    /// Creates a new duration from given raw time unit (see `as_raw`).
    fn from_raw(raw: u64) -> Self;

    /// Returns the value as a raw time unit.
    fn as_raw(&self) -> u64;
}

impl Duration for TimeDuration {
    fn from_raw(nanos: u64) -> Self {
        Self::from_nanos(nanos)
    }

    fn as_raw(&self) -> u64 {
        self.as_nanos() as u64
    }
}

/// A duration in cycles
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct CycleDuration(u64);

impl CycleDuration {
    /// Creates a new duration from given cycle count.
    pub fn new(cycles: u64) -> Self {
        Self(cycles)
    }
}

impl Duration for CycleDuration {
    fn from_raw(cycles: u64) -> Self {
        Self::new(cycles)
    }

    fn as_raw(&self) -> u64 {
        self.0
    }
}

impl fmt::Debug for CycleDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} cycles", self.0)
    }
}
