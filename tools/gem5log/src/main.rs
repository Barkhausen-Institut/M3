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
use std::io::Read;
use std::process::{exit, Command, Stdio};
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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Mode {
    Trace,
    FlameGraph,
    Snapshot,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum ISA {
    X86_64,
    RISCV32,
    RISCV64,
}

fn usage(prog: &str) -> ! {
    eprintln!(
        "Usage: {} (trace|flamegraph|snapshot <time>) [<binary>[+<offset>]...]",
        prog
    );
    exit(1)
}

fn determine_isa(file: &str) -> Result<ISA, error::Error> {
    let mut cmd = Command::new("file")
        .arg("-b")
        .arg(file)
        .stdout(Stdio::piped())
        .spawn()?;
    let stdout = cmd.stdout.as_mut().unwrap();
    let mut res = String::new();
    stdout.read_to_string(&mut res)?;

    if res.contains("x86-64") {
        Ok(ISA::X86_64)
    }
    else if res.contains("32-bit") && res.contains("RISC-V") {
        Ok(ISA::RISCV32)
    }
    else if res.contains("64-bit") && res.contains("RISC-V") {
        Ok(ISA::RISCV64)
    }
    else {
        Err(error::Error::UnknownISA)
    }
}

fn main() -> Result<(), error::Error> {
    let level = Level::from_str(&env::var("RUST_LOG").unwrap_or_else(|_| "error".to_string()))?;
    log::set_boxed_logger(Box::new(Logger { level }))?;
    log::set_max_level(level.to_level_filter());

    let args: Vec<String> = env::args().collect();

    let mode = match args.get(1) {
        Some(mode) if mode == "trace" => Mode::Trace,
        Some(mode) if mode == "flamegraph" => Mode::FlameGraph,
        Some(mode) if mode == "snapshot" => Mode::Snapshot,
        _ => usage(&args[0]),
    };

    let (snapshot_time, bin_start) = if mode == Mode::Snapshot {
        if args.len() < 4 {
            usage(&args[0]);
        }
        let time = args.get(2).expect("Invalid arguments");
        (time.parse::<u64>().expect("Invalid time"), 3)
    }
    else {
        (0, 2)
    };

    let mut isa = None;
    let mut syms = BTreeMap::new();
    for f in &args[bin_start..] {
        let bin_isa = determine_isa(f)?;
        if let Some(isa) = isa {
            if mode != Mode::Trace && bin_isa != isa {
                panic!(
                    "Binaries with different ISAs are not supported for mode {:?}",
                    mode
                );
            }
        }
        isa = Some(bin_isa);

        symbols::parse_symbols(&mut syms, f)?;
    }

    match mode {
        Mode::Trace => trace::generate(&syms),
        Mode::FlameGraph | Mode::Snapshot => {
            flamegraph::generate(mode, snapshot_time, isa.unwrap(), &syms)
        },
    }
}
