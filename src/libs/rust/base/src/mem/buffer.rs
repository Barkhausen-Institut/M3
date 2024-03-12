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

use core::intrinsics;
use core::ops::{Deref, DerefMut};

use crate::cell::StaticUnsafeCell;
use crate::mem;
use crate::util;

pub const MAX_MSG_SIZE: usize = 512;

static DEF_MSG_BUF: StaticUnsafeCell<MsgBuf> = StaticUnsafeCell::new(MsgBuf {
    bytes: [mem::MaybeUninit::new(0); MAX_MSG_SIZE],
    pos: 0,
    used: false,
});

/// A reference to a `MsgBuf` that makes sure that each `MsgBuf` is used at most once at a time.
pub struct MsgBufRef<'m> {
    buf: &'m mut MsgBuf,
}

impl<'m> MsgBufRef<'m> {
    fn new(buf: &'m mut MsgBuf) -> Self {
        assert!(!buf.used);
        buf.used = true;
        Self { buf }
    }
}

impl<'m> Drop for MsgBufRef<'m> {
    fn drop(&mut self) {
        self.buf.pos = 0;
        self.buf.used = false;
    }
}

impl<'m> Deref for MsgBufRef<'m> {
    type Target = MsgBuf;

    fn deref(&self) -> &Self::Target {
        self.buf
    }
}

impl<'m> DerefMut for MsgBufRef<'m> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buf
    }
}

// messages cannot contain a page boundary, so make sure that they are max-size-aligned
#[repr(C, align(512))]
/// A buffer for messages that takes care of proper alignment to fulfill the alignment requirements
/// of the TCU.
pub struct MsgBuf {
    bytes: [mem::MaybeUninit<u8>; MAX_MSG_SIZE],
    pos: usize,
    used: bool,
}

impl MsgBuf {
    /// Borrows the default message buffer
    ///
    /// Every message buffer can only be used once at a time, so that the caller has to make sure
    /// that the returned `MsgBufRef` is dropped before the next call to `borrow_ref`.
    /// Alternatively, `MsgBuf::new` can be used to allocate a new buffer.
    pub fn borrow_def() -> MsgBufRef<'static> {
        // safety: MsgBufRef takes care that there is no other user of DEF_MSG_BUF
        MsgBufRef::new(unsafe { DEF_MSG_BUF.get_mut() })
    }

    /// Creates a new zero'd message buffer containing an empty message
    pub const fn new_initialized() -> Self {
        Self {
            bytes: [mem::MaybeUninit::new(0); MAX_MSG_SIZE],
            pos: 0,
            used: false,
        }
    }

    /// Creates a new message buffer containing an empty message
    pub fn new() -> Self {
        Self {
            bytes: unsafe { mem::MaybeUninit::uninit().assume_init() },
            pos: 0,
            used: false,
        }
    }

    /// Returns the message bytes
    pub fn bytes(&self) -> &[u8] {
        // safety: 0..`pos` is always initialized
        unsafe { intrinsics::transmute(&self.bytes[0..self.pos]) }
    }

    /// Returns the number of bytes to send
    pub fn size(&self) -> usize {
        self.pos
    }

    /// Returns a mutable u64 slice to the message bytes
    ///
    /// # Safety
    ///
    /// The caller cannot read the words since they are not necessarily initialized
    pub unsafe fn words_mut(&mut self) -> &mut [u64] {
        let slice = [self.bytes.as_ptr() as usize, MAX_MSG_SIZE / 8];
        intrinsics::transmute(slice)
    }

    /// Sets the number of bytes that will be sent by the TCU.
    ///
    /// # Safety
    ///
    /// The caller has to guarantee that the bytes from 0 to `pos` are initialized
    pub unsafe fn set_size(&mut self, pos: usize) {
        self.pos = pos;
    }

    /// Casts the message bytes to the given type and returns a reference to it.
    pub fn get<T>(&self) -> &T {
        assert!(mem::align_of::<Self>() >= mem::align_of::<T>());
        assert!(mem::size_of::<Self>() >= mem::size_of::<T>());
        assert!(self.pos >= mem::size_of::<T>());

        // safety: the checks above make sure that the size and alignment is sufficient
        unsafe {
            let bytes: &[u8; MAX_MSG_SIZE] = intrinsics::transmute(&self.bytes);
            let slice = &*(bytes as *const [u8] as *const [T]);
            &slice[0]
        }
    }

    /// Sets the message content to `msg`
    pub fn set<T>(&mut self, msg: T) -> &mut T {
        assert!(mem::align_of::<Self>() >= mem::align_of::<T>());
        assert!(mem::size_of::<Self>() >= mem::size_of::<T>());

        let slice = util::object_to_bytes(&msg);
        mem::MaybeUninit::write_slice(&mut self.bytes[0..slice.len()], slice);
        self.pos = mem::size_of::<T>();

        // safety: we just initialized these bytes and the checks above make sure that the size and
        // alignment is sufficient
        unsafe {
            let bytes: &mut [u8; MAX_MSG_SIZE] = intrinsics::transmute(&mut self.bytes);
            let slice = &mut *(bytes as *mut [u8] as *mut [T]);
            &mut slice[0]
        }
    }

    /// Sets the message to the given slice
    pub fn set_from_slice(&mut self, bytes: &[u8]) {
        mem::MaybeUninit::write_slice(&mut self.bytes[0..bytes.len()], bytes);
        self.pos = bytes.len();
    }
}

impl Clone for MsgBuf {
    fn clone(&self) -> Self {
        let mut copy = Self::new();
        mem::MaybeUninit::write_slice(&mut copy.bytes[0..self.pos], self.bytes());
        copy.pos = self.pos;
        copy
    }
}

#[repr(align(4096))]
/// A buffer that is page aligned in order to maximize performance of TCU transfers.
pub struct AlignedBuf<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> AlignedBuf<N> {
    /// Creates a new `AlignedBuf` filled with zeros
    pub const fn new_zeroed() -> Self {
        Self { data: [0u8; N] }
    }
}

impl<const N: usize> Deref for AlignedBuf<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<const N: usize> DerefMut for AlignedBuf<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}
