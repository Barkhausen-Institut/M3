/*
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

mod error;
mod flamegraph;
mod symbols;
mod trace;

use log::{Level, Log, Metadata, Record};
use std::collections::BTreeMap;
use std::env;
use std::process::exit;
use std::str::FromStr;

struct Logger {
    level: Level,
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            let level_string = record.level().to_string();
            let target = if !record.target().is_empty() {
                record.target()
            }
            else {
                record.module_path().unwrap_or_default()
            };

            eprintln!("{:<5} [{}] {}", level_string, target, record.args());
        }
    }

    fn flush(&self) {
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Mode {
    Trace,
    FlameGraph,
    Snapshot,
}

#[derive(Eq, PartialEq)]
pub enum ISA {
    X86_64,
    RISCV32,
    RISCV64,
}

fn usage(prog: &str) -> ! {
    eprintln!(
        "Usage: {} (x86_64|riscv32|riscv64) (trace|flamegraph|snapshot <time>) [<binary>[+<offset>]...]",
        prog
    );
    exit(1)
}

fn main() -> Result<(), error::Error> {
    let level = Level::from_str(&env::var("RUST_LOG").unwrap_or_else(|_| "error".to_string()))?;
    log::set_boxed_logger(Box::new(Logger { level }))?;
    log::set_max_level(level.to_level_filter());

    let args: Vec<String> = env::args().collect();

    let isa = match args.get(1) {
        Some(isa) if isa == "x86_64" => ISA::X86_64,
        Some(isa) if isa == "riscv32" => ISA::RISCV32,
        Some(isa) if isa == "riscv64" => ISA::RISCV64,
        _ => usage(&args[0]),
    };

    let mode = match args.get(2) {
        Some(mode) if mode == "trace" => Mode::Trace,
        Some(mode) if mode == "flamegraph" => Mode::FlameGraph,
        Some(mode) if mode == "snapshot" => Mode::Snapshot,
        _ => usage(&args[0]),
    };

    let (snapshot_time, bin_start) = if mode == Mode::Snapshot {
        if args.len() < 5 {
            usage(&args[0]);
        }
        let time = args.get(3).expect("Invalid arguments");
        (time.parse::<u64>().expect("Invalid time"), 4)
    }
    else {
        (0, 3)
    };

    let mut syms = BTreeMap::new();
    for f in &args[bin_start..] {
        symbols::parse_symbols(&mut syms, f)?;
    }

    match mode {
        Mode::Trace => trace::generate(&syms),
        Mode::FlameGraph | Mode::Snapshot => flamegraph::generate(mode, snapshot_time, &isa, &syms),
    }
}
