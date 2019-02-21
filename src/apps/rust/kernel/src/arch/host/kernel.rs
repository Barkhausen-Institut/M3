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

use base::cfg;
use base::col::ToString;
use base::dtu;
use base::env;
use base::envdata;
use base::heap;
use base::io;
use base::kif;
use base::libc;
use core::intrinsics;
use thread;

use arch::kdtu;
use arch::loader;
use com;
use mem;
use pes;
use platform;
use tests;
use workloop::workloop;

#[no_mangle]
pub extern "C" fn rust_init(argc: i32, argv: *const *const i8) {
    envdata::set(envdata::EnvData::new(
        0,
        kif::PEDesc::new(kif::PEType::COMP_IMEM, kif::PEISA::X86, 1024 * 1024),
        argc,
        argv
    ));
    heap::init();
    io::init();
    dtu::init();
}

#[no_mangle]
pub extern "C" fn rust_deinit(_status: i32, _arg: *const libc::c_void) {
    dtu::deinit();
}

fn copy_from_fs(path: &str) -> usize {
    unsafe {
        let fd = libc::open(path.as_bytes().as_ptr() as *const i8, libc::O_RDONLY);
        assert!(fd != -1);

        let mut info: libc::stat = intrinsics::uninit();
        assert!(libc::fstat(fd, &mut info) != -1);
        assert!(info.st_size as usize <= cfg::FS_MAX_SIZE);

        let mut alloc = mem::get().allocate_at(0, cfg::FS_MAX_SIZE)
            .expect("Unable to alloc space for FS image");

        let res = libc::read(
            fd,
            alloc.global().offset() as *mut libc::c_void,
            info.st_size as usize
        );
        alloc.claim();
        assert!(res == info.st_size as isize);

        libc::close(fd);

        let fs_size = res as usize;
        klog!(MEM, "Copied fs-image '{}' to 0..{:#x}", path, fs_size);
        fs_size
    }
}

fn copy_to_fs(path: &str, fs_size: usize) {
    let out_path = path.to_string() + ".out";

    unsafe {
        let fd = libc::open(
            out_path.as_bytes().as_ptr() as *const i8,
            libc::O_WRONLY | libc::O_TRUNC | libc::O_CREAT,
            0o600
        );
        assert!(fd != -1);

        let mut alloc = mem::get().allocate_at(0, cfg::FS_MAX_SIZE)
            .expect("Unable to alloc space for FS image");

        libc::write(fd, alloc.global().offset() as *const libc::c_void, fs_size);
        alloc.claim();
        libc::close(fd);
    }

    klog!(MEM, "Copied fs-image back to '{}'", out_path);
}

#[no_mangle]
pub fn main() -> i32 {
    let mut fs_image: Option<&str> = None;

    for arg in env::args() {
        if arg == "test" {
            tests::run();
        }
        if arg.len() > 3 && &arg[0..3] == "fs=" {
            fs_image = Some(&arg[3..]);
        }
    }

    unsafe {
        libc::mkdir("/tmp/m3\0".as_ptr() as *const i8, 0o755);
    }

    com::init();
    mem::init();
    kdtu::KDTU::init();
    platform::init();
    loader::init();
    pes::pemng::init();
    pes::vpemng::init();
    thread::init();

    let fs_size = if let Some(path) = fs_image { copy_from_fs(path) } else { 0 };

    for _ in 0..8 {
        thread::ThreadManager::get().add_thread(workloop as *const () as usize, 0);
    }

    let rbuf = vec![0u8; 512 * 32];
    dtu::DTU::configure_recv(kdtu::KSYS_EP, rbuf.as_ptr() as usize, 14, 9);

    let serv_rbuf = vec![0u8; 1024];
    dtu::DTU::configure_recv(kdtu::KSRV_EP, serv_rbuf.as_ptr() as usize, 10, 8);

    let vpemng = pes::vpemng::get();
    let mut args = env::args();
    args.next();
    vpemng.start(args).expect("init failed");

    klog!(DEF, "Kernel is ready!");

    workloop();

    pes::vpemng::deinit();
    if let Some(path) = fs_image {
        copy_to_fs(path, fs_size);
    }

    klog!(DEF, "Shutting down");
    0
}
