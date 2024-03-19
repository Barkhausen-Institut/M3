/*
 * Copyright (C) 2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019-2022 Nils Asmussen, Barkhausen Institut
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

//! Contains the error handling types

use core::fmt;
use core::intrinsics;

use crate::col::String;
use crate::serialize::{Deserialize, Deserializer, Serialize, Serializer};

/// The error codes
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
pub enum Code {
    // success
    Success = 0,
    // TCU errors
    NoMEP,
    NoSEP,
    NoREP,
    ForeignEP,
    SendReplyEP,
    RecvGone,
    RecvNoSpace,
    RepliesDisabled,
    OutOfBounds,
    NoCredits,
    NoPerm,
    InvMsgOff,
    TranslationFault,
    Abort,
    UnknownCmd,
    RecvOutOfBounds,
    RecvInvReplyEPs,
    SendInvCreditEp,
    SendInvMsgSize,
    TimeoutMem,
    TimeoutNoC,
    PageBoundary,
    MsgUnaligned,
    TLBMiss,
    TLBFull,
    NoPMPEP,
    NoIRQ,
    // SW Errors
    InvArgs,
    ActivityGone,
    OutOfMem,
    NoSuchFile,
    NotSup,
    NoFreeTile,
    InvalidElf,
    NoSpace,
    Exists,
    XfsLink,
    DirNotEmpty,
    IsDir,
    IsNoDir,
    EPInvalid,
    EndOfFile,
    MsgsWaiting,
    UpcallReply,
    CommitFailed,
    NoKernMem,
    NotFound,
    NotRevocable,
    Timeout,
    ReadFailed,
    WriteFailed,
    Utf8Error,
    BadFd,
    SeekPipe,
    Unspecified,
    // networking
    InvState,
    WouldBlock,
    InProgress,
    AlreadyInProgress,
    NotConnected,
    IsConnected,
    InvChecksum,
    SocketClosed,
    ConnectionFailed,
}

impl Default for Code {
    fn default() -> Self {
        Self::Success
    }
}

impl Serialize for Code {
    #[inline(always)]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (*self as u32).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Code {
    #[inline(always)]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::from(u32::deserialize(deserializer)?))
    }
}

// we only use this implementation in debug mode, because it adds a bit of some overhead, errors
// are sometimes used for non-exceptional situations and the backtraces are typically only useful
// in debug mode anyway.

#[cfg(debug_assertions)]
use crate::boxed::Box;
#[cfg(debug_assertions)]
use crate::mem::VirtAddr;

#[cfg(debug_assertions)]
const MAX_BT_LEN: usize = 16;

/// The struct that stores information about an occurred error
#[derive(Clone, Copy)]
#[cfg(debug_assertions)]
pub struct ErrorInfo {
    code: Code,
    bt_len: usize,
    bt: [VirtAddr; MAX_BT_LEN],
}

#[cfg(debug_assertions)]
impl ErrorInfo {
    /// Creates a new object for given error code
    ///
    /// Note that this gathers and stores the backtrace
    #[inline(never)]
    pub fn new(code: Code) -> Self {
        use crate::backtrace;

        let mut bt = [VirtAddr::default(); MAX_BT_LEN];
        let count = backtrace::collect(bt.as_mut());

        ErrorInfo {
            code,
            bt_len: count,
            bt,
        }
    }
}

/// The error struct that is passed around
#[derive(Clone)]
#[cfg(debug_assertions)]
pub struct Error {
    info: Box<ErrorInfo>,
}

#[cfg(debug_assertions)]
impl Error {
    /// Creates a new object for given error code
    ///
    /// Note that this gathers and stores the backtrace
    pub fn new(code: Code) -> Self {
        Error {
            info: Box::new(ErrorInfo::new(code)),
        }
    }

    /// Returns the error code
    pub fn code(&self) -> Code {
        self.info.code
    }

    /// Returns the backtrace to the location where the error occurred
    pub fn backtrace(&self) -> &[VirtAddr] {
        self.info.bt.as_ref()
    }

    fn debug(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{:?} at:", self.code())?;
        for i in 0..self.info.bt_len {
            writeln!(f, "  {:#x}", self.info.bt[i].as_local())?;
        }
        Ok(())
    }
}

// simple and fast implementation for release mode

#[cfg(not(debug_assertions))]
pub struct Error {
    code: Code,
}

#[cfg(not(debug_assertions))]
impl Error {
    /// Creates a new object for given error code
    ///
    /// Note that this gathers and stores the backtrace
    pub fn new(code: Code) -> Self {
        Error { code }
    }

    /// Returns the error code
    pub fn code(&self) -> Code {
        self.code
    }

    fn debug(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.code())
    }
}

impl From<Error> for Code {
    fn from(err: Error) -> Self {
        err.code()
    }
}

impl From<Code> for Result<(), Error> {
    fn from(code: Code) -> Self {
        match code {
            Code::Success => Ok(()),
            e => Err(Error::new(e)),
        }
    }
}

impl<T> From<Result<T, Error>> for Code {
    fn from(res: Result<T, Error>) -> Self {
        match res {
            Ok(_) => Code::Success,
            Err(e) => e.code(),
        }
    }
}

impl From<u32> for Error {
    fn from(error: u32) -> Self {
        Self::new(Code::from(error))
    }
}

impl From<u32> for Code {
    fn from(error: u32) -> Self {
        assert!(error <= Code::ConnectionFailed as u32);
        // safety: assuming that the assert above doesn't fail, the conversion is safe
        // TODO better way?
        unsafe { intrinsics::transmute(error) }
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Error) -> bool {
        self.code() == other.code()
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.debug(f)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.debug(f)
    }
}

/// A verbose error type that contains an error message
pub struct VerboseError {
    code: Code,
    msg: String,
}

impl VerboseError {
    /// Creates a new error with given error code and error message
    pub fn new(code: Code, msg: String) -> Self {
        Self { code, msg }
    }

    /// Returns the error code
    pub fn code(&self) -> Code {
        self.code
    }

    /// Returns the error code
    pub fn msg(&self) -> &String {
        &self.msg
    }

    fn debug(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({:?})", self.msg, self.code)
    }
}

impl From<Error> for VerboseError {
    fn from(e: Error) -> Self {
        Self::new(e.code(), String::default())
    }
}

impl fmt::Debug for VerboseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.debug(f)
    }
}

impl fmt::Display for VerboseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.debug(f)
    }
}
