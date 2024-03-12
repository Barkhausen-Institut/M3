/*
 * Copyright (C) 2022 Nils Asmussen, Barkhausen Institut
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

//! POSIX compatibility layer
//!
//! This compatibility layer is used by our translation layer in musl to translate between Linux
//! system calls and the M³ API.

use core::mem;

use crate::boxed::Box;
use crate::cell::{LazyStaticRefCell, RefMut};
use crate::client::Network;
use crate::errors::{Code, Error};
use crate::io::{read_object, Read, Write};
use crate::libc;
use crate::net::{
    DGramSocket, DgramSocketArgs, Endpoint, IpAddr, Port, Socket, StreamSocket, StreamSocketArgs,
    TcpSocket, UdpSocket,
};
use crate::rc::Rc;
use crate::tiles::{Activity, OwnActivity};
use crate::time::{TimeDuration, TimeInstant};
use crate::util;
use crate::vfs::{
    BufReader, File, FileEvent, FileInfo, FileMode, FileRef, FileWaiter, GenericFile, INodeId,
    OpenFlags, Seek, SeekMode, VFS,
};

macro_rules! try_res {
    ($expr:expr) => {
        match $expr {
            Result::Ok(val) => val,
            Result::Err(err) => {
                return From::from(err);
            },
        }
    };
}

fn get_file(fd: i32) -> Result<FileRef<dyn File>, Error> {
    Activity::own()
        .files()
        .get(fd as usize)
        .ok_or_else(|| Error::new(Code::BadFd))
}

fn get_file_as<T>(fd: i32) -> Result<FileRef<T>, Error> {
    Activity::own()
        .files()
        .get_as(fd as usize)
        .ok_or_else(|| Error::new(Code::BadFd))
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_exit(status: i32, abort: bool) -> ! {
    if abort {
        OwnActivity::abort();
    }
    else {
        match status {
            0 => OwnActivity::exit(Ok(())),
            _ => OwnActivity::exit_with(Code::Unspecified),
        }
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_getpid() -> i32 {
    // + 1, because our ids start with 0, but pid 0 is special
    Activity::own().id() as i32 + 1
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_fstat(fd: i32, info: *mut FileInfo) -> Code {
    let file = try_res!(get_file(fd));
    *info = try_res!(file.stat());
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_stat(pathname: *const i8, info: *mut FileInfo) -> Code {
    *info = try_res!(VFS::stat(util::cstr_to_str(pathname)));
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_mkdir(pathname: *const i8, mode: FileMode) -> Code {
    try_res!(VFS::mkdir(util::cstr_to_str(pathname), mode));
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_rmdir(pathname: *const i8) -> Code {
    try_res!(VFS::rmdir(util::cstr_to_str(pathname)));
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_rename(oldpath: *const i8, newpath: *const i8) -> Code {
    try_res!(VFS::rename(
        util::cstr_to_str(oldpath),
        util::cstr_to_str(newpath)
    ));
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_link(oldpath: *const i8, newpath: *const i8) -> Code {
    try_res!(VFS::link(
        util::cstr_to_str(oldpath),
        util::cstr_to_str(newpath)
    ));
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_unlink(pathname: *const i8) -> Code {
    try_res!(VFS::unlink(util::cstr_to_str(pathname)));
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_opendir(fd: i32, dir: *mut *mut libc::c_void) -> Code {
    let file = try_res!(get_file_as::<GenericFile>(fd));
    *dir = Box::into_raw(Box::new(BufReader::new(file))) as *mut libc::c_void;
    Code::Success
}

const MAX_DIR_NAME_LEN: usize = 28;

#[repr(C, packed)]
pub struct CompatDirEntry {
    inode: INodeId,
    name: [u8; MAX_DIR_NAME_LEN],
}

#[derive(Default)]
#[repr(C, packed)]
struct M3FSDirEntry {
    inode: INodeId,
    name_len: u32,
    next: u32,
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_readdir(dir: *mut libc::c_void, entry: *mut CompatDirEntry) -> Code {
    let dir = dir as *mut BufReader<FileRef<GenericFile>>;

    // read header
    let head: M3FSDirEntry = match read_object(&mut *dir) {
        Ok(obj) => obj,
        Err(_) => return Code::EndOfFile,
    };

    // read name
    (*entry).inode = head.inode;
    let name_len = (head.name_len as usize).min(MAX_DIR_NAME_LEN - 1);
    try_res!((*dir).read_exact(&mut (*entry).name[0..name_len]));
    (*entry).name[name_len] = 0;

    // move to next entry
    let off = head.next as usize - (mem::size_of::<M3FSDirEntry>() + head.name_len as usize);
    if off != 0 && (*dir).seek(off, SeekMode::Cur).is_err() {
        return Code::EndOfFile;
    }

    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_closedir(dir: *mut libc::c_void) -> Code {
    drop(Box::from_raw(dir as *mut BufReader<FileRef<GenericFile>>));
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_chdir(pathname: *const i8) -> Code {
    try_res!(VFS::set_cwd(util::cstr_to_str(pathname)));
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_fchdir(fd: i32) -> Code {
    try_res!(VFS::set_cwd_to(fd as usize));
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_getcwd(buf: *mut u8, size: *mut usize) -> Code {
    let cwd = VFS::cwd();
    if cwd.len() + 1 > *size {
        return Code::NoSpace;
    }
    buf.copy_from(cwd.as_bytes().as_ptr(), cwd.len());
    *buf.add(cwd.len()) = 0;
    *size = cwd.len();
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_open(pathname: *const i8, flags: OpenFlags, fd: *mut i32) -> Code {
    let mut file = try_res!(VFS::open(util::cstr_to_str(pathname), flags));
    file.claim();
    *fd = file.fd() as i32;
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_read(fd: i32, buf: *mut libc::c_void, count: *mut usize) -> Code {
    let mut file = try_res!(get_file(fd));
    let slice = util::slice_for_mut(buf as *mut u8, *count);
    let res = try_res!(file.read(slice));
    *count = res;
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_write(fd: i32, buf: *const libc::c_void, count: *mut usize) -> Code {
    let mut file = try_res!(get_file(fd));
    let slice = util::slice_for(buf as *const u8, *count);
    let res = try_res!(file.write(slice));
    *count = res;
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_fflush(fd: i32) -> Code {
    let mut file = try_res!(get_file(fd));
    try_res!(file.flush());
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_lseek(fd: i32, off: *mut usize, whence: SeekMode) -> Code {
    let mut file = try_res!(get_file(fd));
    *off = try_res!(file.seek(*off, whence));
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_ftruncate(fd: i32, length: usize) -> Code {
    let mut file = try_res!(get_file(fd));
    try_res!(file.truncate(length));
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_truncate(pathname: *const i8, length: usize) -> Code {
    let mut file = try_res!(VFS::open(util::cstr_to_str(pathname), OpenFlags::W));
    try_res!(file.truncate(length));
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_sync(fd: i32) -> Code {
    let mut file = try_res!(get_file(fd));
    try_res!(file.sync());
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_isatty(fd: i32) -> Code {
    let file = try_res!(get_file(fd));
    // try to use the get_tmode operation; only works for vterm
    try_res!(file.get_tmode());
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_close(fd: i32) {
    Activity::own().files().remove(fd as usize);
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_waiter_create(waiter: *mut *mut libc::c_void) -> Code {
    *waiter = Box::into_raw(Box::<FileWaiter>::default()) as *mut libc::c_void;
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_waiter_add(waiter: *mut libc::c_void, fd: i32, events: FileEvent) {
    let waiter = waiter as *mut FileWaiter;
    (*waiter).add(fd as usize, events);
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_waiter_set(waiter: *mut libc::c_void, fd: i32, events: FileEvent) {
    let waiter = waiter as *mut FileWaiter;
    (*waiter).set(fd as usize, events);
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_waiter_rem(waiter: *mut libc::c_void, fd: i32) {
    let waiter = waiter as *mut FileWaiter;
    (*waiter).remove(fd as usize);
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_waiter_wait(waiter: *mut libc::c_void) {
    let waiter = waiter as *mut FileWaiter;
    (*waiter).wait();
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_waiter_waitfor(waiter: *mut libc::c_void, timeout: u64) {
    let waiter = waiter as *mut FileWaiter;
    (*waiter).wait_for(TimeDuration::from_nanos(timeout));
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_waiter_fetch(
    waiter: *mut libc::c_void,
    arg: *mut libc::c_void,
    cb: unsafe extern "C" fn(p: *mut libc::c_void, fd: i32, fdevs: FileEvent),
) {
    let waiter = waiter as *mut FileWaiter;
    (*waiter).foreach_ready(|fd, events| cb(arg, fd as i32, events));
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_waiter_destroy(waiter: *mut libc::c_void) {
    drop(Box::from_raw(waiter as *mut FileWaiter));
}

#[repr(C)]
pub enum CompatSock {
    INVALID,
    DGRAM,
    STREAM,
}

#[repr(C)]
pub struct CompatEndpoint {
    addr: u32,
    port: u16,
}

static NETM: LazyStaticRefCell<Rc<Network>> = LazyStaticRefCell::default();

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_init_netmng(name: *const i8) -> Code {
    if !NETM.is_some() {
        NETM.set(try_res!(Network::new(util::cstr_to_str(name))));
    }
    Code::Success
}

fn create_netmng() -> Result<(), Error> {
    if !NETM.is_some() {
        NETM.set(Network::new("net")?);
    }
    Ok(())
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_socket(ty: CompatSock, fd: *mut i32) -> Code {
    try_res!(create_netmng());

    let mut file = match ty {
        CompatSock::DGRAM => {
            try_res!(UdpSocket::new(DgramSocketArgs::new(NETM.borrow().clone()))).into_generic()
        },
        CompatSock::STREAM => {
            try_res!(TcpSocket::new(StreamSocketArgs::new(NETM.borrow().clone()))).into_generic()
        },
        _ => return Code::NotSup,
    };
    file.claim();
    *fd = file.fd() as i32;
    Code::Success
}

impl From<CompatEndpoint> for Endpoint {
    fn from(ep: CompatEndpoint) -> Self {
        Self::new(IpAddr::new_from_raw(ep.addr), ep.port)
    }
}

impl From<Endpoint> for CompatEndpoint {
    fn from(ep: Endpoint) -> Self {
        Self {
            addr: ep.addr.0,
            port: ep.port,
        }
    }
}

unsafe fn m3_ep_to_compat(m3: Option<Endpoint>, compat: *mut CompatEndpoint) -> Code {
    if let Some(ep) = m3 {
        *compat = CompatEndpoint {
            addr: ep.addr.0,
            port: ep.port,
        };
        Code::Success
    }
    else {
        Code::InvArgs
    }
}

unsafe fn compat_to_m3_ep(compat: *const CompatEndpoint) -> Endpoint {
    Endpoint::new(IpAddr::new_from_raw((*compat).addr), (*compat).port)
}

fn with_socket<F, R>(fd: i32, ty: CompatSock, func: F) -> Result<R, Error>
where
    F: FnOnce(RefMut<'_, dyn Socket>) -> R,
{
    match ty {
        CompatSock::DGRAM => Ok(func(get_file_as::<UdpSocket>(fd)?.borrow_as())),
        CompatSock::STREAM => Ok(func(get_file_as::<TcpSocket>(fd)?.borrow_as())),
        _ => Err(Error::new(Code::InvArgs)),
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_get_local_ep(
    fd: i32,
    ty: CompatSock,
    ep: *mut CompatEndpoint,
) -> Code {
    let m3_ep = try_res!(with_socket(fd, ty, |s| s.local_endpoint()));
    m3_ep_to_compat(m3_ep, ep)
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_get_remote_ep(
    fd: i32,
    ty: CompatSock,
    ep: *mut CompatEndpoint,
) -> Code {
    let m3_ep = try_res!(with_socket(fd, ty, |s| s.remote_endpoint()));
    m3_ep_to_compat(m3_ep, ep)
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_bind_dgram(fd: i32, ep: *const CompatEndpoint) -> Code {
    let mut s = try_res!(get_file_as::<UdpSocket>(fd));
    try_res!(s.bind((*ep).port));
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_accept_stream(
    port: i32,
    cfd: *mut i32,
    ep: *mut CompatEndpoint,
) -> Code {
    try_res!(create_netmng());

    // create a new socket for the to-be-accepted client
    let mut cs = try_res!(TcpSocket::new(StreamSocketArgs::new(NETM.borrow().clone())));

    // put the socket into listen mode
    try_res!(cs.listen(port as Port));

    // accept the client connection
    try_res!(cs.accept());

    cs.claim();
    *cfd = cs.fd() as i32;
    m3_ep_to_compat(cs.remote_endpoint(), ep)
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_connect(fd: i32, ty: CompatSock, ep: *const CompatEndpoint) -> Code {
    try_res!(try_res!(
        with_socket(fd, ty, |mut s| s.connect(compat_to_m3_ep(ep)))
    ));
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_sendto(
    fd: i32,
    ty: CompatSock,
    buf: *const libc::c_void,
    len: *mut usize,
    dest: *const CompatEndpoint,
) -> Code {
    let slice = util::slice_for(buf as *const u8, *len);
    match ty {
        CompatSock::DGRAM => {
            let mut s = try_res!(get_file_as::<UdpSocket>(fd));
            try_res!(s.send_to(slice, compat_to_m3_ep(dest)));
            *len = slice.len();
        },
        CompatSock::STREAM => {
            let mut s = try_res!(get_file_as::<TcpSocket>(fd));
            *len = try_res!(s.send(slice));
        },
        _ => return Code::NotSup,
    }
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_recvfrom(
    fd: i32,
    ty: CompatSock,
    buf: *mut libc::c_void,
    len: *mut usize,
    ep: *mut CompatEndpoint,
) -> Code {
    let slice = util::slice_for_mut(buf as *mut u8, *len);
    match ty {
        CompatSock::DGRAM => {
            let mut s = try_res!(get_file_as::<UdpSocket>(fd));
            let (res, src) = try_res!(s.recv_from(slice));
            m3_ep_to_compat(Some(src), ep);
            *len = res;
        },
        CompatSock::STREAM => {
            let mut s = try_res!(get_file_as::<TcpSocket>(fd));
            m3_ep_to_compat(s.remote_endpoint(), ep);
            *len = try_res!(s.recv(slice));
        },
        _ => return Code::NotSup,
    }
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_abort_stream(fd: i32) -> Code {
    let mut s = try_res!(get_file_as::<TcpSocket>(fd));
    try_res!(s.abort());
    Code::Success
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_get_nanos() -> u64 {
    TimeInstant::now().as_nanos()
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_get_time(secs: *mut i32, nanos: *mut isize) {
    let now = TimeInstant::now();
    *secs = (now.as_nanos() / 1_000_000_000) as i32;
    *nanos = now.as_nanos() as isize - (*secs as isize * 1_000_000_000);
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_sleep(secs: *mut i32, nanos: *mut isize) {
    let start = TimeInstant::now();

    let allnanos = *nanos as u64 + *secs as u64 * 1_000_000_000;
    OwnActivity::sleep_for(TimeDuration::from_nanos(allnanos)).unwrap();

    let duration = TimeInstant::now().duration_since(start);
    let remaining = TimeDuration::from_nanos(allnanos).saturating_sub(duration);
    *secs = remaining.as_secs() as i32;
    *nanos = remaining.as_nanos() as isize - (*secs as isize * 1_000_000_000);
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_print_syscall_start(
    name: *const i8,
    a: isize,
    b: isize,
    c: isize,
    d: isize,
    e: isize,
    f: isize,
) {
    println!(
        "{}({}, {}, {}, {}, {}, {}) ...",
        util::cstr_to_str(name),
        a,
        b,
        c,
        d,
        e,
        f
    );
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_print_syscall_end(
    name: *const i8,
    res: isize,
    a: isize,
    b: isize,
    c: isize,
    d: isize,
    e: isize,
    f: isize,
) {
    println!(
        "{}({}, {}, {}, {}, {}, {}) -> {}",
        util::cstr_to_str(name),
        a,
        b,
        c,
        d,
        e,
        f,
        res
    );
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn __m3c_print_syscall_trace(
    idx: usize,
    name: *const i8,
    no: isize,
    start: u64,
    end: u64,
) {
    println!(
        "[{:3}] {}({}) {:011} {:011}",
        idx,
        util::cstr_to_str(name),
        no,
        start,
        end,
    );
}
