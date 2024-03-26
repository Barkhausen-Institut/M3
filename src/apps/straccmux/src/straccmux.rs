/*
 * Copyright (C) 2024 Nils Asmussen, Barkhausen Institut
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

#[allow(unused_extern_crates)]
extern crate lang;

mod proto;

use core::arch::asm;
use core::ptr;

use base::cell::{StaticCell, StaticRefCell};
use base::cfg;
use base::env;
use base::errors::{Code, Error};
use base::io::{self, LogFlags};
use base::kif;
use base::log;
use base::machine;
use base::mem::{MsgBuf, VirtAddr, VirtAddrRaw};
use base::serialize::{Deserialize, M3Deserializer};
use base::tcu;

extern "C" {
    fn __m3_init_libc(argc: i32, argv: *const *const u8, envp: *const *const u8, tls: bool);
    fn __m3_heap_set_area(begin: usize, end: usize);
}

#[no_mangle]
pub extern "C" fn abort() {
    exit(1);
}

#[no_mangle]
pub extern "C" fn exit(_code: i32) -> ! {
    machine::write_coverage(0);
    loop {
        tcu::TCU::sleep().unwrap();
    }
}

fn kpex_rbuf_addr() -> VirtAddr {
    env::boot().tile_desc().rbuf_mux_space().0
}

fn side_rbuf_addr() -> VirtAddr {
    VirtAddr::new(
        env::boot().tile_desc().rbuf_mux_space().0.as_raw() + cfg::KPEX_RBUF_SIZE as VirtAddrRaw,
    )
}

fn get_request<'de, R: Deserialize<'de>>(msg: &'static tcu::Message) -> Result<R, Error> {
    let mut de = M3Deserializer::new(msg.as_words());
    de.skip(1);
    de.pop()
}

fn get_reply<'de, R: Deserialize<'de>>(msg: &'static tcu::Message) -> Result<R, Error> {
    let mut de = M3Deserializer::new(msg.as_words());
    de.pop()
}

fn reply_msg(msg: &'static tcu::Message, reply: &MsgBuf) {
    let msg_off = tcu::TCU::msg_to_offset(side_rbuf_addr(), msg);
    tcu::TCU::reply(tcu::TMSIDE_REP, reply, msg_off).unwrap();
}

fn receive<'de, R: Deserialize<'de>>(ep: tcu::EpId, rbuf: VirtAddr) -> Result<R, Error> {
    loop {
        if let Some(msg_off) = tcu::TCU::fetch_msg(ep) {
            let msg = tcu::TCU::offset_to_msg(rbuf, msg_off);
            let reply: R = get_reply(msg).unwrap();
            tcu::TCU::ack_msg(ep, msg_off).unwrap();
            return Ok(reply);
        }
    }
}

struct AccelAct {
    id: tcu::ActId,
    ep_off: tcu::EpId,
    used_eps: u32,
    exec: proto::Executor,
}

impl AccelAct {
    fn exit(&self) {
        let mut msg_buf = MsgBuf::borrow_def();
        base::build_vmsg!(msg_buf, kif::tilemux::Calls::Exit, kif::tilemux::Exit {
            act_id: self.id,
            status: Code::Success,
        });
        tcu::TCU::send(tcu::KPEX_SEP, &msg_buf, 0, tcu::KPEX_REP).unwrap();
        receive::<()>(tcu::KPEX_REP, kpex_rbuf_addr()).unwrap();
    }
}

#[derive(Clone, Copy, Debug)]
enum State {
    Init,
    Running(tcu::Reg),
}

static ACT: StaticRefCell<Option<AccelAct>> = StaticRefCell::new(None);
static STATE: StaticCell<State> = StaticCell::new(State::Init);

fn stop_activity(id: tcu::ActId) {
    if let Some(act) = ACT.borrow_mut().take() {
        assert!(act.id == id);
        act.exit();
        STATE.set(State::Init);
    }
}

fn activity_init(msg: &'static tcu::Message) -> Result<(), Error> {
    let r: kif::tilemux::ActInit = get_request(msg)?;

    log!(
        LogFlags::MuxSideCalls,
        "sidecall::activity_init(act={})",
        r.act_id,
    );

    *ACT.borrow_mut() = Some(AccelAct {
        id: r.act_id as tcu::ActId,
        ep_off: 32,
        used_eps: 0,
        exec: proto::Executor::new(32),
    });
    Ok(())
}

fn activity_ctrl(msg: &'static tcu::Message) -> Result<(), Error> {
    let r: kif::tilemux::ActivityCtrl = get_request(msg)?;

    log!(
        LogFlags::MuxSideCalls,
        "sidecall::activity_ctrl(act={}, op={:?})",
        r.act_id,
        r.act_op,
    );

    match r.act_op {
        kif::tilemux::ActivityOp::Start => {
            STATE.set(State::Running(r.act_id as tcu::Reg));
            Ok(())
        },

        _ => {
            stop_activity(r.act_id as tcu::ActId);
            Ok(())
        },
    }
}

fn request_ep(msg: &'static tcu::Message) -> Result<tcu::EpId, Error> {
    let r: kif::tilemux::ReqEP = get_request(msg)?;

    log!(
        LogFlags::MuxSideCalls,
        "sidecall::request_ep(act={}, ep_id={}, replies={})",
        r.act_id,
        r.ep_id,
        r.replies,
    );

    if let Some(act) = ACT.borrow_mut().as_mut() {
        for i in r.ep_id as usize..r.ep_id as usize + 1 + r.replies {
            if (act.used_eps & (1 << i)) != 0 {
                return Err(Error::new(Code::Exists));
            }
        }

        for i in r.ep_id as usize..r.ep_id as usize + 1 + r.replies {
            act.used_eps |= 1 << i;
        }
        Ok(act.ep_off + r.ep_id)
    }
    else {
        Err(Error::new(Code::NotFound))
    }
}

fn shutdown(_msg: &'static tcu::Message) -> Result<(), Error> {
    log!(LogFlags::MuxSideCalls, "sidecall::shutdown()");
    Ok(())
}

fn handle_sidecall(msg: &'static tcu::Message) -> bool {
    let mut de = M3Deserializer::new(msg.as_words());

    let mut done = false;
    let mut val1 = 0;
    let val2 = 0;
    let op: kif::tilemux::Sidecalls = de.pop().unwrap();

    let res = match op {
        kif::tilemux::Sidecalls::Info => {
            val1 = kif::syscalls::MuxType::Accel.into();
            Ok(())
        },
        kif::tilemux::Sidecalls::ActInit => activity_init(msg),
        kif::tilemux::Sidecalls::ActCtrl => activity_ctrl(msg),
        kif::tilemux::Sidecalls::ReqEP => request_ep(msg).map(|epid| {
            val1 = epid as u64;
        }),
        kif::tilemux::Sidecalls::Shutdown => {
            shutdown(msg).unwrap();
            done = true;
            Ok(())
        },
        _ => {
            log!(LogFlags::MuxSideCalls, "sidecall::{:?}: ignoring", op);
            Ok(())
        },
    };

    let mut reply_buf = MsgBuf::borrow_def();
    base::build_vmsg!(
        reply_buf,
        match res {
            Ok(_) => Code::Success,
            Err(e) => {
                log!(LogFlags::MuxSideCalls, "sidecall {:?} failed: {}", op, e);
                e.code()
            },
        },
        kif::tilemux::Response { val1, val2 }
    );
    reply_msg(msg, &reply_buf);
    done
}

#[no_mangle]
pub extern "C" fn env_run() {
    unsafe {
        __m3_init_libc(0, ptr::null(), ptr::null(), false);
    }

    io::init(env::boot().tile_id(), "saccmux");

    log!(
        LogFlags::Info,
        "Hello from the stream accelerator multiplexer!"
    );

    loop {
        if let Some(msg_off) = tcu::TCU::fetch_msg(tcu::TMSIDE_REP) {
            let msg = tcu::TCU::offset_to_msg(side_rbuf_addr(), msg_off);
            if handle_sidecall(msg) {
                break;
            }
        }

        match STATE.get() {
            State::Init => {},
            State::Running(mut act_reg) => {
                let id = (act_reg & 0xFFFF) as tcu::ActId;

                let old = tcu::TCU::xchg_activity(act_reg).unwrap();
                assert!(old >> 16 == 0);

                let done = {
                    if let Some(act) = ACT.borrow_mut().as_mut() {
                        !act.exec.step()
                    }
                    else {
                        false
                    }
                };

                act_reg = tcu::TCU::xchg_activity(old).unwrap();
                assert!(act_reg >> 16 == 0);

                if done {
                    stop_activity(id);
                }
            },
        }
    }

    // do a wfi here directly after shutdown, so that we hopefully don't execute any code while the
    // kernel resets the tile. this is actually just a workaround for gem5, where we cannot reset
    // the core properly.
    unsafe {
        asm!(
            "csrw   sip, x0",
            "li     t0, 1 << 5",
            "csrc   sstatus, t0",
            "1:     wfi",
            "j      1b",
        );
    }

    unreachable!();
}
