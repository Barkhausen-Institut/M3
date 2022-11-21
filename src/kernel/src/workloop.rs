/*
 * Copyright (C) 2020-2022 Nils Asmussen, Barkhausen Institut
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

use base::envdata;
use base::tcu;

use crate::com;
use crate::ktcu;
use crate::syscalls;
use crate::tiles::ActivityMng;

pub fn thread_startup() {
    workloop();
}

pub fn workloop() -> ! {
    if thread::cur().is_main() {
        // ActivityMng::start_root_async().expect("starting root failed");
        Some(ActivityMng::start_linux_async().expect("starting linux failed"));
    }

    while ActivityMng::count() > 0 {
        if envdata::get().platform != envdata::Platform::HW.val {
            tcu::TCU::sleep().unwrap();
        }

        if let Some(msg) = ktcu::fetch_msg(ktcu::KSYS_EP) {
            syscalls::handle_async(msg);
        }

        if let Some(msg) = ktcu::fetch_msg(ktcu::KSRV_EP) {
            unsafe {
                let squeue: *mut com::SendQueue = msg.header.label as usize as *mut _;
                (*squeue).received_reply(msg);
            }
        }

        #[cfg(not(target_vendor = "host"))]
        if let Some(msg) = ktcu::fetch_msg(ktcu::KPEX_EP) {
            let tile = msg.header.label as tcu::TileId;
            crate::tiles::TileMux::handle_call_async(crate::tiles::tilemng::tilemux(tile), msg);
        }

        thread::try_yield();

        #[cfg(target_vendor = "host")]
        crate::arch::childs::check_childs_async();
        #[cfg(target_vendor = "host")]
        crate::arch::net::check();
        #[cfg(target_vendor = "host")]
        crate::arch::input::check();
    }

    thread::stop();
    // if we get back here, there is no ready or sleeping thread anymore and we can shutdown
    crate::arch::kernel::shutdown();
}
