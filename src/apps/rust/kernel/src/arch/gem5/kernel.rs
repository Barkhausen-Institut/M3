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

use base::env;
use base::goff;
use base::io;
use base::mem::heap;
use thread;

use arch::kdtu;
use arch::loader;
use arch::vm;
use com;
use mem;
use pes;
use platform;
use workloop::workloop;

extern {
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
    heap::init();
    vm::init();
    io::init();
    mem::init();

    com::init();
    kdtu::KDTU::init();
    platform::init();
    loader::init();
    pes::pemng::init();
    pes::vpemng::init();
    thread::init();

    for _ in 0..8 {
        thread::ThreadManager::get().add_thread(workloop as *const () as usize, 0);
    }

    let sysc_rbuf = vec![0u8; 512 * 32];
    kdtu::KDTU::get().recv_msgs(kdtu::KSYS_EP, sysc_rbuf.as_ptr() as goff, 14, 9)
        .expect("Unable to config syscall REP");

    let serv_rbuf = vec![0u8; 1024];
    kdtu::KDTU::get().recv_msgs(kdtu::KSRV_EP, serv_rbuf.as_ptr() as goff, 10, 8)
        .expect("Unable to config service REP");

    let vpemng = pes::vpemng::get();
    let mut args = env::args();
    args.next();

    vpemng.start(args).expect("init failed");

    klog!(DEF, "Kernel is ready!");

    workloop();

    pes::vpemng::deinit();
    klog!(DEF, "Shutting down");
    exit(0);
}
