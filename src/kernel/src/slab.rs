/*
 * Copyright (C) 2020-2021 Nils Asmussen, Barkhausen Institut
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

use base::cell::LazyStaticRefCell;
use base::libc;
use base::mem;
use core::ptr::{self, NonNull};

extern "C" {
    fn malloc(size: usize) -> *mut libc::c_void;
    fn calloc(n: usize, size: usize) -> *mut libc::c_void;
    fn realloc(p: *mut libc::c_void, size: usize) -> *mut libc::c_void;
    fn free(p: *mut libc::c_void);
}

pub const HEADER_SIZE: usize = 16;
const NEW_AREA_COUNT: usize = 64;

#[repr(C)]
struct Area {
    slab: NonNull<Slab>,
    next: Option<NonNull<Area>>,
    #[cfg(target_arch = "arm")]
    _pad: u64,
    user: u64,
}

struct Slab {
    free: Option<NonNull<Area>>,
    size: Option<usize>,
}

impl Slab {
    fn new(size: Option<usize>) -> Self {
        base::const_assert!(mem::size_of::<Area>() == HEADER_SIZE + 8);
        Self { free: None, size }
    }

    unsafe fn heap_to_area(&mut self, ptr: *mut libc::c_void) -> *mut Area {
        assert_ne!(ptr, ptr::null_mut());
        #[allow(clippy::cast_ptr_alignment)]
        let res = ptr as *mut Area;
        (*res).slab = NonNull::new_unchecked(self as *mut _);
        res
    }

    unsafe fn user_addr(area: *mut Area) -> *mut libc::c_void {
        &mut (*area).user as *mut _ as *mut libc::c_void
    }

    #[inline(never)]
    unsafe fn extend(&mut self, objsize: usize) {
        let area_size = objsize + HEADER_SIZE;
        #[allow(clippy::cast_ptr_alignment)]
        let mut a = malloc(area_size * NEW_AREA_COUNT) as *mut Area;
        assert_ne!(a, ptr::null_mut());
        for _ in 0..NEW_AREA_COUNT {
            (*a).next = self.free;
            (*a).slab = NonNull::new_unchecked(self as *mut _);
            self.free = NonNull::new(a);
            a = ((a as usize) + area_size) as *mut Area;
        }
    }

    unsafe fn alloc(&mut self, size: usize) -> *mut libc::c_void {
        let area = match self.size {
            Some(objsize) => {
                if self.free.is_none() {
                    self.extend(objsize);
                }

                let res = self.free.unwrap();
                self.free = (*res.as_ptr()).next;
                res.as_ptr()
            },

            None => self.heap_to_area(malloc(size + HEADER_SIZE)),
        };

        Self::user_addr(area)
    }

    unsafe fn calloc(&mut self, size: usize) -> *mut libc::c_void {
        match self.size {
            Some(_) => unimplemented!(),

            None => {
                let ptr = calloc(size + HEADER_SIZE, 1);
                Self::user_addr(self.heap_to_area(ptr))
            },
        }
    }

    unsafe fn free(&mut self, area: *mut Area) {
        match self.size {
            Some(_) => {
                (*area).next = self.free;
                self.free = NonNull::new(area);
            },

            None => free(area as *mut libc::c_void),
        }
    }

    unsafe fn realloc(
        &mut self,
        area: *mut Area,
        old_size: usize,
        new_size: usize,
    ) -> *mut libc::c_void {
        match self.size {
            Some(_) => {
                let nptr = malloc(new_size + HEADER_SIZE);
                let narea = SLAB_ALL.borrow_mut().heap_to_area(nptr);
                let res = Self::user_addr(narea);
                libc::memcpy(res, Self::user_addr(area), old_size);
                self.free(area);
                res
            },

            None => {
                let ptr = realloc(area as *mut libc::c_void, new_size + HEADER_SIZE);
                Self::user_addr(self.heap_to_area(ptr))
            },
        }
    }
}

static SLAB_64: LazyStaticRefCell<Slab> = LazyStaticRefCell::default();
static SLAB_128: LazyStaticRefCell<Slab> = LazyStaticRefCell::default();
static SLAB_ALL: LazyStaticRefCell<Slab> = LazyStaticRefCell::default();

pub fn init() {
    SLAB_64.set(Slab::new(Some(64)));
    SLAB_128.set(Slab::new(Some(128)));
    SLAB_ALL.set(Slab::new(None));
}

unsafe fn get_area(ptr: *mut libc::c_void) -> *mut Area {
    (ptr as usize - HEADER_SIZE) as *mut Area
}

#[no_mangle]
extern "C" fn __rdl_alloc(size: usize, _align: usize, _err: *mut u8) -> *mut libc::c_void {
    let mut slab = if size <= 64 {
        SLAB_64.borrow_mut()
    }
    else if size <= 128 {
        SLAB_128.borrow_mut()
    }
    else {
        SLAB_ALL.borrow_mut()
    };
    let res = unsafe { slab.alloc(size) };
    klog!(
        SLAB,
        "alloc(sz={}, s={:?}) -> {:#x}",
        size,
        slab.size,
        res as usize
    );
    res
}

#[no_mangle]
unsafe extern "C" fn __rdl_dealloc(ptr: *mut libc::c_void, _size: usize, _align: usize) {
    let area = get_area(ptr);
    let slab = &mut *(*area).slab.as_ptr();
    klog!(SLAB, "free(p={:#x}, s={:?})", ptr as usize, slab.size);
    slab.free(area);
}

#[no_mangle]
unsafe extern "C" fn __rdl_realloc(
    ptr: *mut libc::c_void,
    old_size: usize,
    _old_align: usize,
    new_size: usize,
    _new_align: usize,
    _err: *mut u8,
) -> *mut libc::c_void {
    let area = get_area(ptr);
    let slab = &mut *(*area).slab.as_ptr();
    klog!(SLAB, "realloc(p={:#x}, s={:?})", ptr as usize, slab.size);
    slab.realloc(area, old_size, new_size)
}

#[no_mangle]
extern "C" fn __rdl_alloc_zeroed(size: usize, _align: usize, _err: *mut u8) -> *mut libc::c_void {
    let res = unsafe { SLAB_ALL.borrow_mut().calloc(size) };
    klog!(
        SLAB,
        "calloc(sz={}, s={:?}) -> {:#x}",
        size,
        SLAB_ALL.borrow().size,
        res as usize
    );
    res
}
