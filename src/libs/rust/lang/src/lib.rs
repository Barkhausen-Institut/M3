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

#![no_std]
#![allow(internal_features)]
#![feature(alloc_error_handler)]
#![feature(core_intrinsics)]
#![feature(lang_items)]
#![feature(panic_info_message)]

use core::intrinsics;
use core::panic::PanicInfo;

use base::backtrace;
use base::cell::StaticCell;
use base::io::{log, Write};
use base::mem::VirtAddr;

extern "C" {
    fn abort();
    fn exit(code: i32);
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    static PANIC: StaticCell<bool> = StaticCell::new(false);
    if PANIC.get() {
        unsafe {
            abort();
        }
    }

    PANIC.set(true);

    // disable instruction trace here to see the instructions that lead to the panic
    if base::env::boot().platform == base::env::Platform::Hw {
        base::tcu::TCU::set_trace_instrs(false);
    }

    if let Some(mut l) = log::Log::get() {
        if let Some(loc) = info.location() {
            l.write_fmt(format_args!(
                "PANIC at {}:{}:{}: ",
                loc.file(),
                loc.line(),
                loc.column()
            ))
            .unwrap();
        }
        else {
            l.write(b"PANIC at unknown location: ").unwrap();
        }
        if let Some(msg) = info.message() {
            l.write_fmt(*msg).unwrap();
        }
        l.write(b"\n\n").unwrap();

        let mut bt = [VirtAddr::default(); 16];
        let bt_len = backtrace::collect(&mut bt);
        l.write(b"Backtrace:\n").unwrap();
        for addr in bt.iter().take(bt_len) {
            l.write_fmt(format_args!("  {:#x}\n", addr.as_local()))
                .unwrap();
        }
    }

    unsafe {
        exit(1);
    }
    intrinsics::abort();
}

#[alloc_error_handler]
fn alloc_error(_: core::alloc::Layout) -> ! {
    panic!("Alloc error");
}

#[lang = "eh_personality"]
#[no_mangle]
#[doc(hidden)]
pub extern "C" fn rust_eh_personality() {
    intrinsics::abort()
}

#[no_mangle]
#[doc(hidden)]
pub extern "C" fn _Unwind_Resume() -> ! {
    intrinsics::abort()
}
