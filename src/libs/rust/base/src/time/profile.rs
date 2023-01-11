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

//! Contains types to simplify profiling

use core::fmt;

use crate::col::Vec;
use crate::math;
use crate::time::{Duration, Instant};

/// A container for the measured execution times
pub struct Results<T: Duration> {
    times: Vec<T>,
}

impl<T: Duration> Results<T> {
    /// Creates an empty result container for the given number of runs
    pub fn new(runs: usize) -> Self {
        Results {
            times: Vec::with_capacity(runs),
        }
    }

    /// Pushes the given time to the container
    pub fn push(&mut self, time: T) {
        self.times.push(time);
    }

    /// Returns the number of runs
    pub fn runs(&self) -> usize {
        self.times.len()
    }

    /// Returns the arithmetic mean of the runtimes
    pub fn avg(&self) -> T {
        let mut sum = 0;
        for t in &self.times {
            sum += t.as_raw();
        }
        if self.times.is_empty() {
            T::from_raw(sum)
        }
        else {
            T::from_raw(sum / (self.times.len() as u64))
        }
    }

    /// Returns the standard deviation of the runtimes
    pub fn stddev(&self) -> T {
        let mut sum = 0;
        let average = self.avg().as_raw();
        for t in &self.times {
            let val = if t.as_raw() < average {
                average - t.as_raw()
            }
            else {
                t.as_raw() - average
            };
            sum += val * val;
        }
        if self.times.is_empty() {
            T::from_raw(0)
        }
        else {
            T::from_raw(math::sqrt((sum as f32) / (self.times.len() as f32)) as u64)
        }
    }

    pub fn filter_outliers(&mut self) {
        let avg = self.avg().as_raw();
        self.times.retain(|t| t.as_raw() > avg / 2 && t.as_raw() < avg * 2);
    }

    pub fn min_max(&self) -> (T, T) {
        let mut min = !0u64;
        let mut max = 0;
        for t in &self.times {
            let r = t.as_raw();
            if r < min {
                min = r;
            }
            if r > max {
                max = r;
            }
        }
        return (T::from_raw(min), T::from_raw(max));
    }
}

impl<T: Duration> fmt::Display for Results<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (min, max) = self.min_max();
        write!(
            f,
            "{:?} (+/- {:?} with {} runs, min: {:?}, max: {:?})",
            self.avg(),
            self.stddev(),
            self.runs(),
            min,
            max,
        )
    }
}

// for printing every single value
impl<T: Duration> fmt::Debug for Results<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for t in &self.times {
            writeln!(f, "{:?}", t)?;
        }
        Ok(())
    }
}

/// Allows to measure execution times
///
/// # Examples
///
/// Simple usage:
///
/// ```
/// use base::profile;
///
/// let mut prof = profile::Profiler::default();
/// println!("{}", prof.run::<CycleInstant, _>(|| /* my benchmark */));
/// ```
///
/// Advanced usage:
///
/// ```
/// use base::profile;
///
/// #[derive(Default)]
/// struct Tester();
///
/// impl profile::Runner for Tester {
///     fn run(&mut self) {
///         // my benchmark
///     }
///     fn post(&mut self) {
///         // my cleanup action
///     }
/// }
///
/// let mut prof = profile::Profiler::default().repeats(10).warmup(2);
/// println!("{}", prof.runner::<CycleInstant, _>(&mut Tester::default()));
/// ```
pub struct Profiler {
    repeats: u64,
    warmup: u64,
}

/// A runner is used to run the benchmarks and allows to perform pre- and post-actions.
pub trait Runner {
    /// Is executed before the benchmark
    fn pre(&mut self) {
    }

    /// Executes the benchmark
    fn run(&mut self);

    /// Is executed after the benchmark
    fn post(&mut self) {
    }
}

impl Profiler {
    /// Sets the number of runs to `repeats`
    pub fn repeats(mut self, repeats: u64) -> Self {
        self.repeats = repeats;
        self
    }

    /// Sets the number of warmup runs to `warmup`
    pub fn warmup(mut self, warmup: u64) -> Self {
        self.warmup = warmup;
        self
    }

    /// Runs `func` as benchmark and returns the result
    #[inline(always)]
    pub fn run<T: Instant, F: FnMut()>(&self, mut func: F) -> Results<T::Duration> {
        let mut res = Results::new((self.warmup + self.repeats) as usize);
        for i in 0..self.warmup + self.repeats {
            let start = T::now();
            func();
            let end = T::now();

            if i >= self.warmup {
                res.push(end.duration_since(start));
            }
        }
        res
    }

    /// Runs the given runner as benchmark and returns the result
    #[inline(always)]
    pub fn runner<T: Instant, R: Runner>(&self, runner: &mut R) -> Results<T::Duration> {
        let mut res = Results::new((self.warmup + self.repeats) as usize);
        for i in 0..self.warmup + self.repeats {
            runner.pre();

            let start = T::now();
            runner.run();
            let end = T::now();

            runner.post();

            if i >= self.warmup {
                res.push(end.duration_since(start));
            }
        }
        res
    }
}

impl Default for Profiler {
    /// Creates a default profiler with 100 runs and 10 warmup runs
    fn default() -> Self {
        Profiler {
            repeats: 100,
            warmup: 10,
        }
    }
}
