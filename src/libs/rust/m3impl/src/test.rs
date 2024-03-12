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

//! Contains unittest utilities inspired by [`WvTest`](https://github.com/apenwarr/wvtest)

use core::fmt::{Display, Formatter};

/// Runs the tests
pub trait WvTester {
    /// Runs the given test suite
    fn run_suite(&mut self, name: &str, f: &dyn Fn(&mut dyn WvTester));
    /// Runs the given test
    fn run_test(&mut self, name: &str, file: &str, f: &dyn Fn(&mut dyn WvTester));
    /// Is called on succeeded failures
    fn test_succeeded(&mut self);
    /// Is called on test failures
    fn test_failed(&mut self);
}

/// The default implementation for the [`WvTester`]
#[derive(Default, Copy, Clone, Debug)]
pub struct DefaultWvTester {
    tests: u64,
    fails: u64,
}

impl DefaultWvTester {
    pub fn tests(&self) -> u64 {
        self.tests
    }

    pub fn failures(&self) -> u64 {
        self.fails
    }

    pub fn successes(&self) -> u64 {
        self.tests - self.fails
    }
}

impl WvTester for DefaultWvTester {
    fn run_suite(&mut self, name: &str, f: &dyn Fn(&mut dyn WvTester)) {
        println!("Running test suite {} ...\n", name);
        f(self);
        println!();
    }

    fn run_test(&mut self, name: &str, file: &str, f: &dyn Fn(&mut dyn WvTester)) {
        println!("Testing \"{}\" in {}:", name, file);
        f(self);
        println!();
    }

    fn test_succeeded(&mut self) {
        self.tests += 1;
    }

    fn test_failed(&mut self) {
        self.tests += 1;
        self.fails += 1;
    }
}

impl Display for DefaultWvTester {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        if self.failures() > 0 {
            write!(
                f,
                "\x1B[1;31m{} of {} tests failed\x1B[0;m",
                self.failures(),
                self.tests()
            )
        }
        else {
            write!(f, "\x1B[1;32mAll tests successful!\x1B[0;m")
        }
    }
}

/// Convenience macro that calls [`WvTester::run_suite`](WvTester::run_suite) and uses the function
/// name as suite name
#[macro_export]
macro_rules! wv_run_suite {
    ($t:expr, $func:path) => {
        $t.run_suite(stringify!($func), &$func)
    };
}

/// Convenience macro that calls [`WvTester::run_test`](WvTester::run_test) and uses the function
/// name as test name
#[macro_export]
macro_rules! wv_run_test {
    ($t:expr, $func:path) => {
        $t.run_test(stringify!($func), file!(), &$func)
    };
}

/// Convenience macro that runs the given benchmark and reports the result
#[macro_export]
macro_rules! wv_perf {
    ($name:expr, $bench:expr) => {
        // ensure that we evaluate the expression before println in case it contains a println
        let name = $name;
        let bench_result = $bench;
        ::m3::println!(
            "! {}:{}  PERF \"{}\": {}",
            file!(),
            line!(),
            name,
            bench_result
        );
    };
}

/// Convenience macro that tests whether $a is true and reports failures
#[macro_export]
macro_rules! wv_assert {
    ($t:expr, $a:expr) => {{
        match (&$a) {
            (a_val) => {
                if !*a_val {
                    ::m3::println!("! {}:{}  {:?} FAILED", file!(), line!(), &*a_val);
                    $t.test_failed();
                }
                else {
                    $t.test_succeeded();
                }
            },
        }
    }};
}

/// Convenience macro that tests whether $a and $b are equal and reports failures
#[macro_export]
macro_rules! wv_assert_eq {
    ($t:expr, $a:expr, $b:expr) => ({
        match (&$a, &$b) {
            (a_val, b_val) => {
                if *a_val != *b_val {
                    ::m3::println!("! {}:{}  {:?} == {:?} FAILED", file!(), line!(), &*a_val, &*b_val);
                    $t.test_failed();
                }
                else {
                    $t.test_succeeded();
                }
            }
        }
    });

    ($t:expr, $a:expr, $b:expr, $($arg:tt)+) => ({
        match (&$a, &$b) {
            (a_val, b_val) => {
                if *a_val != *b_val {
                    ::m3::println!("! {}:{}  {} FAILED", file!(), line!(), format_args!($($arg)+));
                    $t.test_failed();
                }
                else {
                    $t.test_succeeded();
                }
            }
        }
    });
}

/// Convenience macro that tests whether the argument is [`Ok`], returns the inner value if so, and
/// panics otherwise
#[macro_export]
macro_rules! wv_assert_ok {
    ($res:expr) => {{
        let res = $res;
        match res {
            Ok(r) => r,
            Err(e) => {
                ::m3::println!(
                    "! {}:{}  expected Ok for {}, got {:?} FAILED",
                    file!(),
                    line!(),
                    stringify!($res),
                    e
                );
                panic!("Stopping tests here.")
            },
        }
    }};
}

/// Convenience macro that tests whether the argument is [`Some`], returns the inner value if so,
/// and panics otherwise
#[macro_export]
macro_rules! wv_assert_some {
    ($res:expr) => {{
        let res = $res;
        match res {
            Some(r) => r,
            None => {
                ::m3::println!(
                    "! {}:{}  expected Some for {}, received None FAILED",
                    file!(),
                    line!(),
                    stringify!($res)
                );
                panic!("Stopping tests here.")
            },
        }
    }};
}

/// Convenience macro that tests whether the argument is [`Err`] with the given error code
#[macro_export]
macro_rules! wv_assert_err {
    ($t:expr, $res:expr, $err:expr) => {{
        let res = $res;
        match res {
            Ok(r) => {
                ::m3::println!("! {}:{}  received okay: {:?} FAILED", file!(), line!(), r);
                $t.test_failed();
            },
            Err(ref e) if e.code() != $err => {
                ::m3::println!(
                    "! {}:{}  received error {:?}, expected {:?} FAILED",
                    file!(),
                    line!(),
                    e,
                    $err
                );
                $t.test_failed();
            },
            Err(_) => {
                $t.test_succeeded();
            },
        }
    }};
    ($t:expr, $res:expr, $err1:expr, $err2:expr) => {{
        let res = $res;
        match res {
            Ok(r) => {
                ::m3::println!("! {}:{}  received okay: {:?} FAILED", file!(), line!(), r);
                $t.test_failed();
            },
            Err(ref e) if e.code() != $err1 && e.code() != $err2 => {
                ::m3::println!(
                    "! {}:{}  received error {:?}, expected {:?} or {:?} FAILED",
                    file!(),
                    line!(),
                    e,
                    $err1,
                    $err2
                );
                $t.test_failed();
            },
            Err(_) => {
                $t.test_succeeded();
            },
        }
    }};
}
