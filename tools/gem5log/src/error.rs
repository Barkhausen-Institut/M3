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

use std::fmt;
use std::io;
use std::num;

pub enum Error {
    Io(io::Error),
    ParseNum(num::ParseIntError),
    LogLevel(log::ParseLevelError),
    SetLog(log::SetLoggerError),
    Nm(i32),
    UnknownISA,
    InvalPath,
    Internal,
}

macro_rules! impl_err {
    ($src:ty, $dst:tt) => {
        impl From<$src> for Error {
            fn from(error: $src) -> Self {
                Error::$dst(error)
            }
        }
    };
}

impl_err!(io::Error, Io);
impl_err!(num::ParseIntError, ParseNum);
impl_err!(log::ParseLevelError, LogLevel);
impl_err!(log::SetLoggerError, SetLog);

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Error::Io(e) => write!(fmt, "I/O error occurred: {}", e),
            Error::ParseNum(e) => write!(fmt, "Unable to parse number: {}", e),
            Error::SetLog(e) => write!(fmt, "Setting logger failed: {}", e),
            Error::LogLevel(e) => write!(fmt, "Parsing log level failed: {}", e),
            Error::Nm(c) => write!(fmt, "nm -SC <bin> failed: {}", c),
            Error::UnknownISA => write!(fmt, "unknown ISA"),
            Error::InvalPath => write!(fmt, "path is invalid"),
            Error::Internal => write!(fmt, "internal error"),
        }
    }
}
