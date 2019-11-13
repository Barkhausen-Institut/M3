/*
 * Copyright (C) 2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
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

use base::goff;
use base::io;
use base::math;
use base::mem::heap;
use thread;

use arch::{exceptions, loader, paging};
use ktcu;
use mem;
use pes;
use platform;
use workloop::{thread_startup, workloop};

extern "C" {
    pub fn gem5_shutdown(delay: u64);
}

#[no_mangle]
pub extern "C" fn exit(_code: i32) {
    unsafe {
        gem5_shutdown(0);
    }
}

#[no_mangle]
pub extern "C" fn env_run() {
    exceptions::init();
    heap::init();
    io::init(0, "rkernel");
    paging::init();
    mem::init();

    platform::init(&[]);
    loader::init();

    thread::init();
    for _ in 0..8 {
        thread::ThreadManager::get().add_thread(thread_startup as *const () as usize, 0);
    }

    pes::pemng::init();
    pes::vpemng::init();

    // TODO add second syscall REP
    let sysc_rbuf = vec![0u8; 512 * 32];
    ktcu::recv_msgs(ktcu::KSYS_EP, sysc_rbuf.as_ptr() as goff, 14, 9)
        .expect("Unable to config syscall REP");

    let serv_rbuf = vec![0u8; 1024];
    ktcu::recv_msgs(ktcu::KSRV_EP, serv_rbuf.as_ptr() as goff, 10, 8)
        .expect("Unable to config service REP");

    let pex_rbuf_ord = math::next_log2(32) + pes::MSG_ORD;
    let pex_rbuf = vec![0u8; 1 << pex_rbuf_ord];
    ktcu::recv_msgs(
        ktcu::KPEX_EP,
        pex_rbuf.as_ptr() as goff,
        pex_rbuf_ord,
        pes::MSG_ORD,
    )
    .expect("Unable to config pemux REP");

    let vpemng = pes::vpemng::get();
    vpemng.start_root().expect("starting root failed");

    klog!(DEF, "Kernel is ready!");

    workloop();

    pes::vpemng::deinit();
    klog!(DEF, "Shutting down");
    exit(0);
}
