/*
 * Copyright (C) 2021, Stephan Gerhold <stephan.gerhold@mailbox.tu-dresden.de>
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

use base::{
    cpu::{CPUOps, CPU},
    crypto::{HashAlgorithm, HashType},
};
use core::sync::atomic;

const STATE_SIZE: usize = 256;

/// Represents a saved state of the KecAcc accelerator.
#[derive(Clone)]
#[repr(align(256))]
pub struct KecAccState {
    data: [u8; STATE_SIZE],
}

impl KecAccState {
    pub const fn new() -> Self {
        Self {
            data: [0u8; STATE_SIZE],
        }
    }
}

const MAX_ADDR: *const u8 = (1 << 30) as *const u8;
const MAX_SIZE: usize = 1 << 30;

enum CmdType {
    /// Accelerator is idle (has completed previous command)
    _Idle,
    /// Initialize accelerator with specified hash type
    Init,
    /// Load accelerator state from specified memory address
    Load,
    ///Save accelerator state to specified memory address
    Save,
    /// Absorb bytes from specified memory address
    Absorb,
    /// Absorb last few bytes from specified memory address and apply padding
    AbsorbLast,
    /// Squeeze bytes to specified memory address
    Squeeze,
}

struct Cmd(u64);

impl Cmd {
    fn init(hash_type: u8) -> Self {
        assert!(hash_type <= 0xf);
        Cmd(CmdType::Init as u64 | (hash_type << 4) as u64)
    }

    fn state(cmd: CmdType, state: &KecAccState) -> Self {
        assert!(state.data.as_ptr() < MAX_ADDR);
        Cmd(cmd as u64 | (state.data.as_ptr() as u64) << 4)
    }

    fn sponge(cmd: CmdType, buf: &[u8]) -> Self {
        assert!(buf.as_ptr() < MAX_ADDR);
        assert!(buf.len() < MAX_SIZE);
        Cmd(cmd as u64 | (buf.as_ptr() as u64) << 4 | (buf.len() as u64) << 34)
    }
}

/// A simple wrapper around the Keccak/SHA-3 accelerator ("KecAcc"), mapped
/// to the specified memory address.
/// NOTE: All the functions start the operation asynchronously (only waiting
/// for previous commands to complete) so [poll_complete()] should be used
/// if the result of the accelerator should be available before proceeding.
pub struct KecAcc {
    addr: usize,
}

impl KecAcc {
    pub const fn new(addr: usize) -> Self {
        KecAcc { addr }
    }

    pub fn supports_algo(&self, _algo: &HashAlgorithm) -> bool {
        true
    }

    pub fn is_busy(&self) -> bool {
        unsafe { CPU::read8b(self.addr as *const u64) != 0 }
    }

    pub fn poll_complete(&self) {
        while self.is_busy() {}
    }

    pub fn poll_complete_barrier(&self) {
        self.poll_complete();

        // Make sure the accelerator is actually done and has written back
        // its result. Without this computing a SHA3-512 hash on x86_64 returns
        // the previous contents of the buffer instead of the generated hash.
        atomic::fence(atomic::Ordering::SeqCst);
    }

    fn start_cmd(&self, cmd: Cmd) {
        self.poll_complete();
        unsafe {
            CPU::write8b(self.addr as *mut u64, cmd.0);
        }
    }

    pub fn start_init(&self, hash_type: HashType) {
        self.start_cmd(Cmd::init(hash_type as u8));
    }

    pub fn start_load(&self, state: &KecAccState) {
        self.start_cmd(Cmd::state(CmdType::Load, state));
    }

    pub fn start_save(&self, state: &mut KecAccState) {
        self.start_cmd(Cmd::state(CmdType::Save, state));
    }

    pub fn start_absorb(&self, buf: &[u8]) {
        self.start_cmd(Cmd::sponge(CmdType::Absorb, buf));
    }

    pub fn start_pad(&self) {
        self.start_cmd(Cmd(CmdType::AbsorbLast as u64));
    }

    pub fn start_absorb_last(&self, buf: &[u8]) {
        self.start_cmd(Cmd::sponge(CmdType::AbsorbLast, buf));
    }

    pub fn start_squeeze(&self, buf: &mut [u8]) {
        self.start_cmd(Cmd::sponge(CmdType::Squeeze, buf));
    }
}
