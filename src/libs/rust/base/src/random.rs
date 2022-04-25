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

//! Contains random number generators

use crate::time::TimeInstant;

/// Linear congruential generator.
///
/// Source: `<http://en.wikipedia.org/wiki/Linear_congruential_generator>`
#[derive(Debug)]
pub struct LCG {
    a: u32,
    c: u32,
    last: u32,
}

impl LCG {
    /// Creates a new LCG with given seed
    pub fn new(seed: u32) -> Self {
        Self {
            a: 1103515245,
            c: 12345,
            last: seed,
        }
    }

    /// Returns the next pseudo random number
    pub fn get(&mut self) -> u32 {
        self.last = self.a * self.last + self.c;
        return (self.last / 65536) % 32768;
    }
}

impl Default for LCG {
    fn default() -> Self {
        Self::new(TimeInstant::now().as_nanos() as u32)
    }
}
