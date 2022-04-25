/*
 * Copyright (C) 2020-2022 Nils Asmussen, Barkhausen Institut
 * Copyright (C) 2019-2020, Tendsin Mende <tendsin@protonmail.com>
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

#![feature(core_intrinsics)]
#![no_std]

#[macro_use]
extern crate m3;

mod backend;
mod buf;
mod data;
mod ops;
mod sess;

use crate::backend::{Backend, DiskBackend, MemBackend};
use crate::buf::{FileBuffer, MetaBuffer};
use crate::data::{Allocator, SuperBlock};
use crate::sess::{FSSession, M3FSSession, MetaSession, OpenFiles};

use base::cell::LazyStaticUnsafeCell;
use m3::{
    boxed::Box,
    cap::Selector,
    cell::{LazyReadOnlyCell, LazyStaticRefCell, Ref, RefMut, StaticRefCell},
    col::{String, ToString, Vec},
    com::{GateIStream, RecvGate},
    env,
    errors::{Code, Error},
    goff,
    server::{
        server_loop, CapExchange, Handler, RequestHandler, Server, SessId, SessionContainer,
        DEF_MAX_CLIENTS,
    },
    tcu::Label,
    tiles::Activity,
    vfs::{FSOperation, GenFileOp},
};

// Sets the logging behavior
pub const LOG_DEF: bool = false;
pub const LOG_SESSION: bool = false;
pub const LOG_ALLOC: bool = false;
pub const LOG_BUFFER: bool = false;
pub const LOG_DIRS: bool = false;
pub const LOG_INODES: bool = false;
pub const LOG_LINKS: bool = false;
pub const LOG_FIND: bool = false;

// Server constants
const FS_IMG_OFFSET: goff = 0;
const MSG_SIZE: usize = 128;

// The global request handler
static REQHDL: LazyReadOnlyCell<RequestHandler> = LazyReadOnlyCell::default();

static SB: LazyStaticRefCell<SuperBlock> = LazyStaticRefCell::default();
// TODO we unfortunately need to use an unsafe cell here at the moment, because the meta buffer is
// basicalled used in all modules, making it really hard to use something like a RefCell here.
static MB: LazyStaticUnsafeCell<MetaBuffer> = LazyStaticUnsafeCell::default();
static FB: LazyStaticRefCell<FileBuffer> = LazyStaticRefCell::default();
static FILES: StaticRefCell<OpenFiles> = StaticRefCell::new(OpenFiles::new());
static BA: LazyStaticRefCell<Allocator> = LazyStaticRefCell::default();
static IA: LazyStaticRefCell<Allocator> = LazyStaticRefCell::default();
static SETTINGS: LazyReadOnlyCell<FsSettings> = LazyReadOnlyCell::default();
static BACKEND: LazyStaticRefCell<Box<dyn Backend>> = LazyStaticRefCell::default();

fn superblock() -> Ref<'static, SuperBlock> {
    SB.borrow()
}
fn superblock_mut() -> RefMut<'static, SuperBlock> {
    SB.borrow_mut()
}
fn meta_buffer_mut() -> &'static mut MetaBuffer {
    // safety: see comment for MB
    unsafe { MB.get_mut() }
}
fn file_buffer_mut() -> RefMut<'static, FileBuffer> {
    FB.borrow_mut()
}
fn open_files_mut() -> RefMut<'static, OpenFiles> {
    FILES.borrow_mut()
}
fn blocks_mut() -> RefMut<'static, Allocator> {
    BA.borrow_mut()
}
fn inodes_mut() -> RefMut<'static, Allocator> {
    IA.borrow_mut()
}
fn settings() -> &'static FsSettings {
    SETTINGS.get()
}
fn backend_mut() -> RefMut<'static, Box<dyn Backend>> {
    BACKEND.borrow_mut()
}

fn flush_buffer() -> Result<(), Error> {
    crate::meta_buffer_mut().flush()?;
    crate::file_buffer_mut().flush()?;

    // update superblock and write it back to disk/memory
    let mut sb = crate::superblock_mut();
    let inodes = crate::inodes_mut();
    sb.update_inodebm(inodes.free_count(), inodes.first_free());
    let blocks = crate::blocks_mut();
    sb.update_blockbm(blocks.free_count(), blocks.first_free());
    sb.checksum = sb.get_checksum();
    crate::backend_mut().store_sb(&*sb)
}

int_enum! {
    pub struct M3FSOperation : u64 {
        const STAT          = GenFileOp::STAT.val;
        const SEEK          = GenFileOp::SEEK.val;
        const NEXT_IN       = GenFileOp::NEXT_IN.val;
        const NEXT_OUT      = GenFileOp::NEXT_OUT.val;
        const COMMIT        = GenFileOp::COMMIT.val;
        const TRUNCATE      = GenFileOp::TRUNCATE.val;
        const SYNC          = GenFileOp::SYNC.val;
        const CLOSE         = GenFileOp::CLOSE.val;
        const CLONE         = GenFileOp::CLONE.val;
        const GET_PATH      = GenFileOp::GET_PATH.val;
        const SET_TMODE     = GenFileOp::SET_TMODE.val;
        const SET_DEST      = GenFileOp::SET_DEST.val;
        const ENABLE_NOTIFY = GenFileOp::ENABLE_NOTIFY.val;
        const REQ_NOTIFY    = GenFileOp::REQ_NOTIFY.val;
        const OPEN          = FSOperation::OPEN.val;
        const FSTAT         = FSOperation::STAT.val;
        const MKDIR         = FSOperation::MKDIR.val;
        const RMDIR         = FSOperation::RMDIR.val;
        const LINK          = FSOperation::LINK.val;
        const UNLINK        = FSOperation::UNLINK.val;
        const RENAME        = FSOperation::RENAME.val;
        const GET_MEM       = FSOperation::GET_MEM.val;
        const GET_SGATE     = FSOperation::GET_SGATE.val;
        const DEL_EP        = FSOperation::DEL_EP.val;
        const OPEN_PRIV     = FSOperation::OPEN_PRIV.val;
    }
}

struct M3FSRequestHandler {
    sel: Selector,
    sessions: SessionContainer<FSSession>,
}

impl M3FSRequestHandler {
    fn new(mut backend: Box<dyn Backend>) -> Result<Self, Error> {
        // init thread manager, otherwise the waiting within the file and meta buffer impl. panics.
        thread::init();

        let sb = backend.load_sb().expect("Unable to load super block");
        log!(crate::LOG_DEF, "Loaded {:#?}", sb);

        BA.set(Allocator::new(
            String::from("Block"),
            sb.first_blockbm_block(),
            sb.first_free_block,
            sb.free_blocks,
            sb.total_blocks,
            sb.blockbm_blocks(),
            sb.block_size as usize,
        ));
        IA.set(Allocator::new(
            String::from("INodes"),
            sb.first_inodebm_block(),
            sb.first_free_inode,
            sb.free_inodes,
            sb.total_inodes,
            sb.inodebm_block(),
            sb.block_size as usize,
        ));

        // safety: we pass in a newly constructed MetaBuffer and have not initialized MB before
        unsafe {
            MB.set(MetaBuffer::new(sb.block_size as usize));
        }
        FB.set(FileBuffer::new(sb.block_size as usize));
        SB.set(sb);

        BACKEND.set(backend);

        let container = SessionContainer::new(DEF_MAX_CLIENTS);

        Ok(M3FSRequestHandler {
            sel: 0, // gets set later in main
            sessions: container,
        })
    }

    pub fn handle(&mut self, op: M3FSOperation, input: &mut GateIStream<'_>) -> Result<(), Error> {
        log!(LOG_DEF, "[{}] fs::handle(op={})", input.label(), op);

        let res = match op {
            M3FSOperation::NEXT_IN => self.exec_on_sess(input, |sess, is| sess.next_in(is)),
            M3FSOperation::NEXT_OUT => self.exec_on_sess(input, |sess, is| sess.next_out(is)),
            M3FSOperation::COMMIT => self.exec_on_sess(input, |sess, is| sess.commit(is)),
            M3FSOperation::TRUNCATE => self.exec_on_sess(input, |sess, is| sess.truncate(is)),
            M3FSOperation::CLOSE => match self.exec_on_sess(input, |sess, is| sess.close(is)) {
                Ok(true) => {
                    // get session id, then notify caller that we closed, finally close self
                    let sid = input.label() as SessId;
                    input.reply_error(Code::None).ok();
                    self.close_session(sid, input.rgate())
                },
                Ok(false) => Ok(()),
                Err(e) => Err(e),
            },
            M3FSOperation::STAT => self.exec_on_sess(input, |sess, is| sess.stat(is)),
            M3FSOperation::GET_PATH => self.exec_on_sess(input, |sess, is| sess.get_path(is)),
            M3FSOperation::SEEK => self.exec_on_sess(input, |sess, is| sess.seek(is)),
            M3FSOperation::FSTAT => self.exec_on_sess(input, |sess, is| sess.fstat(is)),
            M3FSOperation::MKDIR => self.exec_on_sess(input, |sess, is| sess.mkdir(is)),
            M3FSOperation::RMDIR => self.exec_on_sess(input, |sess, is| sess.rmdir(is)),
            M3FSOperation::LINK => self.exec_on_sess(input, |sess, is| sess.link(is)),
            M3FSOperation::UNLINK => self.exec_on_sess(input, |sess, is| sess.unlink(is)),
            M3FSOperation::RENAME => self.exec_on_sess(input, |sess, is| sess.rename(is)),
            M3FSOperation::SYNC => self.exec_on_sess(input, |sess, is| sess.sync(is)),
            M3FSOperation::OPEN_PRIV => self.exec_on_sess(input, |sess, is| sess.open_priv(is)),
            _ => Err(Error::new(Code::InvArgs)),
        };

        if let Err(ref e) = res {
            input.reply_error(e.code()).ok();
        }

        log!(
            LOG_DEF,
            "[{}] fs::handle(op={}) -> {:?}",
            input.label(),
            op,
            res.as_ref().map_err(|e| e.code()),
        );
        Ok(())
    }

    fn exec_on_sess<F, R>(&mut self, is: &mut GateIStream<'_>, function: F) -> Result<R, Error>
    where
        F: Fn(&mut FSSession, &mut GateIStream<'_>) -> Result<R, Error>,
    {
        let session_id: SessId = is.label() as SessId;
        if let Some(sess) = self.sessions.get_mut(session_id) {
            function(sess, is)
        }
        else {
            Err(Error::new(Code::InvArgs))
        }
    }

    fn close_session(&mut self, sid: SessId, rgate: &RecvGate) -> Result<(), Error> {
        // close this and all child sessions
        let mut sids = vec![sid];
        while let Some(id) = sids.pop() {
            if let Ok(sess) = self.remove_session(id) {
                log!(crate::LOG_DEF, "[{}] fs::close(): closing {}", sid, id);

                match sess {
                    FSSession::Meta(ref meta) => {
                        // remove contained file sessions
                        sids.extend_from_slice(meta.file_sessions());
                    },

                    FSSession::File(ref file) => {
                        // remove file session from parent meta session
                        if let Some(parent_meta_session) = self.sessions.get_mut(file.meta_sess()) {
                            match parent_meta_session {
                                FSSession::Meta(ref mut pms) => pms.remove_file(id),
                                _ => panic!("FileSession's parent is not a MetaSession!?"),
                            }
                        }

                        // remove file session from parent file session
                        if let Some(psid) = file.parent_sess() {
                            if let Some(parent_file_session) = self.sessions.get_mut(psid) {
                                match parent_file_session {
                                    FSSession::File(ref mut pfs) => pfs.remove_child(id),
                                    _ => panic!("Parent FileSession is not a FileSession!?"),
                                }
                            }
                        }

                        // remove child file sessions
                        sids.extend_from_slice(file.child_sessions());
                    },
                }

                // ignore all potentially outstanding messages of this session
                rgate.drop_msgs_with(id as Label);
            }
        }
        Ok(())
    }

    fn remove_session(&mut self, sid: SessId) -> Result<FSSession, Error> {
        let session = self
            .sessions
            .get_mut(sid)
            .ok_or_else(|| Error::new(Code::InvArgs))?;

        let creator = session.creator();
        Ok(self.sessions.remove(creator, sid))
    }
}

impl Handler<FSSession> for M3FSRequestHandler {
    fn sessions(&mut self) -> &mut SessionContainer<FSSession> {
        &mut self.sessions
    }

    /// Creates a new session with `arg` as an argument for the service with selector `srv_sel`.
    ///
    /// Returns the session selector and the session identifier.
    fn open(
        &mut self,
        crt: usize,
        srv_sel: Selector,
        arg: &str,
    ) -> Result<(Selector, SessId), Error> {
        // get max number of files
        let mut max_files: usize = 16;
        if arg.len() > 6 && &arg[..6] == "files=" {
            max_files = arg[6..].parse().map_err(|_| Error::new(Code::InvArgs))?;
        }

        // get the id this session would belong to.
        let sessid = self.sessions.next_id()?;

        self.sessions.add_next(crt, srv_sel, true, |sess| {
            log!(
                crate::LOG_SESSION,
                "[{}] creating session(crt={}, max_files={})",
                sess.ident(),
                crt,
                max_files
            );
            Ok(FSSession::Meta(MetaSession::new(
                sess, sessid, crt, max_files,
            )))
        })
    }

    /// Let's the client obtain a capability from the server
    fn obtain(&mut self, crt: usize, sid: SessId, data: &mut CapExchange<'_>) -> Result<(), Error> {
        // get some values now, because we cannot borrow self while holding the session reference
        let next_sess_id = self.sessions.next_id()?;
        let sel: Selector = self.sel;

        let op: M3FSOperation = data.in_args().pop()?;
        log!(LOG_DEF, "[{}] fs::obtain(crt={}, op={})", sid, crt, op);

        if !self.sessions.can_add(crt) {
            return Err(Error::new(Code::NoSpace));
        }

        let session = self
            .sessions
            .get_mut(sid)
            .ok_or_else(|| Error::new(Code::InvArgs))?;
        match session {
            FSSession::Meta(meta) => match op {
                M3FSOperation::GET_SGATE => meta.get_sgate(data, REQHDL.get().recv_gate()),
                M3FSOperation::OPEN => {
                    let file_session =
                        meta.open_file(sel, crt, data, next_sess_id, REQHDL.get().recv_gate())?;

                    self.sessions
                        .add(crt, next_sess_id, FSSession::File(file_session))
                },
                _ => Err(Error::new(Code::InvArgs)),
            },

            FSSession::File(file) => match op {
                M3FSOperation::CLONE => {
                    let nfile_session =
                        file.clone(sel, crt, next_sess_id, data, REQHDL.get().recv_gate())?;

                    self.sessions
                        .add(crt, next_sess_id, FSSession::File(nfile_session))
                },
                M3FSOperation::GET_MEM => file.get_mem(data),
                _ => Err(Error::new(Code::InvArgs)),
            },
        }
    }

    /// Let's the client delegate a capability to the server
    fn delegate(
        &mut self,
        _crt: usize,
        sid: SessId,
        data: &mut CapExchange<'_>,
    ) -> Result<(), Error> {
        let op: M3FSOperation = data.in_args().pop()?;
        log!(LOG_DEF, "[{}] fs::delegate(op={})", sid, op);

        let session = self
            .sessions
            .get_mut(sid)
            .ok_or_else(|| Error::new(Code::InvArgs))?;
        match session {
            FSSession::File(fs) => match op {
                M3FSOperation::SET_DEST => {
                    if data.in_caps() != 1 {
                        return Err(Error::new(Code::NotSup));
                    }

                    let new_sel: Selector = Activity::own().alloc_sel();
                    fs.set_ep(new_sel);
                    data.out_caps(m3::kif::CapRngDesc::new(
                        m3::kif::CapType::OBJECT,
                        new_sel,
                        1,
                    ));
                },
                M3FSOperation::ENABLE_NOTIFY => return Err(Error::new(Code::NotSup)),
                _ => return Err(Error::new(Code::InvArgs)),
            },
            FSSession::Meta(m) => match op {
                M3FSOperation::DEL_EP => {
                    if data.in_caps() != 1 {
                        return Err(Error::new(Code::NotSup));
                    }

                    let new_sel: Selector = Activity::own().alloc_sel();
                    let id = m.add_ep(new_sel);
                    data.out_caps(m3::kif::CapRngDesc::new(
                        m3::kif::CapType::OBJECT,
                        new_sel,
                        1,
                    ));
                    data.out_args().push(&id);
                },
                M3FSOperation::ENABLE_NOTIFY => return Err(Error::new(Code::NotSup)),
                _ => return Err(Error::new(Code::InvArgs)),
            },
        }

        Ok(())
    }

    fn close(&mut self, _crt: usize, sid: SessId) {
        self.close_session(sid, REQHDL.get().recv_gate()).ok();
    }

    fn shutdown(&mut self) {
        crate::flush_buffer().expect("buffer flush at shutdown failed");
    }
}

#[derive(Clone, Debug)]
pub struct FsSettings {
    name: String,
    backend: String,
    fs_size: usize,
    extend: usize,
    max_load: usize,
    max_clients: usize,
    clear: bool,
    selector: Option<Selector>,
    fs_offset: goff,
}

impl core::default::Default for FsSettings {
    fn default() -> Self {
        FsSettings {
            name: String::from("m3fs"),
            backend: String::from("mem"),
            fs_size: 0,
            extend: 128,
            max_load: 128,
            max_clients: DEF_MAX_CLIENTS,
            clear: false,
            selector: None,
            fs_offset: FS_IMG_OFFSET,
        }
    }
}

fn usage() -> ! {
    println!(
        "Usage: {} [-n <name>] [-s <sel>] [-e <blocks>] [-c] [-b <blocks>]",
        env::args().next().unwrap()
    );
    println!("       [-o <offset>] [-m <clients>] (disk|mem <fssize>)");
    println!();
    println!("  -n: the name of the service (m3fs by default)");
    println!("  -s: don't create service, use selectors <sel>..<sel+1>");
    println!("  -e: the number of blocks to extend files when appending");
    println!("  -c: clear allocated blocks");
    println!("  -b: the maximum number of blocks loaded from the disk");
    println!("  -o: the file system offset in DRAM");
    println!("  -m: the maximum number of clients (receive slots)");
    m3::exit(1);
}

fn parse_args() -> Result<FsSettings, String> {
    let mut settings = FsSettings::default();

    let args: Vec<&str> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i] {
            "-n" => settings.name = args[i + 1].to_string(),
            "-s" => {
                if let Ok(s) = args[i + 1].parse::<Selector>() {
                    settings.selector = Some(s);
                }
            },
            "-e" => {
                settings.extend = args[i + 1]
                    .parse::<usize>()
                    .map_err(|_| String::from("Could not parse FS extend"))?;
            },
            "-b" => {
                settings.max_load = args[i + 1]
                    .parse::<usize>()
                    .map_err(|_| String::from("Could not parse max load"))?;
            },
            "-o" => {
                settings.fs_offset = args[i + 1]
                    .parse::<goff>()
                    .map_err(|_| String::from("Failed to parse FS offset"))?;
            },
            "-m" => {
                settings.max_clients = args[i + 1]
                    .parse::<usize>()
                    .map_err(|_| String::from("Failed to parse client count"))?;
            },
            "-c" => {
                settings.clear = true;
                i -= 1; // argument has no value
            },
            _ => break,
        }
        // move forward 2 by default, since most arguments have a value
        i += 2;
    }

    settings.backend = args[i].to_string();
    match settings.backend.as_str() {
        "mem" => {
            settings.fs_size = args[i + 1]
                .parse::<usize>()
                .map_err(|_| String::from("Failed to parse fs size"))?;
        },
        "disk" => {},
        backend => return Err(format!("Unknown backend {}", backend)),
    }

    Ok(settings)
}

#[no_mangle]
pub fn main() -> i32 {
    // parse arguments
    SETTINGS.set(parse_args().unwrap_or_else(|e| {
        println!("Invalid arguments: {}", e);
        usage();
    }));
    log!(crate::LOG_DEF, "{:#?}", SETTINGS.get());

    // create backend for the file system
    let mut hdl = if SETTINGS.get().backend == "mem" {
        let backend = Box::new(MemBackend::new(
            SETTINGS.get().fs_offset,
            SETTINGS.get().fs_size,
        ));
        M3FSRequestHandler::new(backend)
            .expect("Failed to create m3fs handler based on memory backend")
    }
    else {
        let backend = Box::new(DiskBackend::new().expect("Failed to initialize disk backend!"));
        M3FSRequestHandler::new(backend)
            .expect("Failed to create m3fs handler based on disk backend")
    };

    // create new server for file system and pass on selector to handler
    let serv =
        Server::new(&SETTINGS.get().name, &mut hdl).expect("Could not create service 'm3fs'");
    hdl.sel = serv.sel();

    // create request handler
    REQHDL.set(
        RequestHandler::new_with(SETTINGS.get().max_clients, MSG_SIZE)
            .expect("Unable to create request handler"),
    );

    server_loop(|| {
        // handle message that is given to the server
        serv.handle_ctrl_chan(&mut hdl)?;
        REQHDL.get().handle(|op, is| hdl.handle(op, is))
    })
    .ok();

    0
}
