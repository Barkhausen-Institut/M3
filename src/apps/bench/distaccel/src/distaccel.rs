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

use m3::{
    chan::data::{
        self as datachan, BlockReceiver, BlockSender, Receiver, ReceiverCap, ReceiverDesc, Sender,
        SenderCap, SenderDesc,
    },
    col::{String, ToString, Vec},
    env,
    errors::Error,
    io::LogFlags,
    log,
    mem::{GlobOff, VirtAddr},
    serialize::{Deserialize, Serialize},
    tiles::{Activity, ActivityArgs, ChildActivity, RunningActivity, RunningProgramActivity, Tile},
    time::{Profiler, TimeInstant},
    vec, wv_perf,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "m3::serde")]
struct NodeConfig {
    name: String,
    recv: ReceiverDesc,
    send: Option<SenderDesc>,
}

fn create_activity<S: AsRef<str>>(name: S) -> Result<ChildActivity, Error> {
    let tile = Tile::get("compat")?;
    ChildActivity::new_with(tile, ActivityArgs::new(name.as_ref()))
}

fn start_activity<S: ToString>(
    name: S,
    mut act: ChildActivity,
    recv: &ReceiverCap,
    send: Option<&SenderCap>,
    func: fn() -> Result<(), Error>,
) -> Result<RunningProgramActivity, Error> {
    recv.delegate(&act)?;
    if let Some(send) = send {
        send.delegate(&act)?;
    }

    let mut dst = act.data_sink();
    dst.push(NodeConfig {
        name: name.to_string(),
        recv: recv.desc(),
        send: send.map(|s| s.desc()),
    });

    act.run(func)
}

fn compute_node() -> Result<(), Error> {
    let mut src = Activity::own().data_source();
    let cfg: NodeConfig = src.pop().unwrap();

    let recv = Receiver::new(cfg.name.clone(), cfg.recv).unwrap();
    let mut send = cfg.send.map(|s| Sender::new(cfg.name.clone(), s).unwrap());

    log!(LogFlags::Debug, "{}: starting", cfg.name);

    for blk in recv.iter::<(), u8>() {
        if let Some(send) = send.as_mut() {
            send.send(blk, ()).unwrap();
        }
    }

    log!(LogFlags::Debug, "{}: finished", cfg.name);

    Ok(())
}

const CREDITS: u32 = 1;
const MSG_SIZE: usize = 128;
const BUF_ADDR: VirtAddr = VirtAddr::new(0x3000_0000);

fn pipeline(buf_size: GlobOff) -> Result<(), Error> {
    let n1 = create_activity("n1").unwrap();
    let n2 = create_activity("n2").unwrap();

    let (n0n1_s, n0n1_r) = datachan::create(&n1, MSG_SIZE, CREDITS, BUF_ADDR, buf_size).unwrap();
    let (n1n2_s, n1n2_r) = datachan::create(&n2, MSG_SIZE, CREDITS, BUF_ADDR, buf_size).unwrap();
    let (n2n0_s, n2n0_r) =
        datachan::create(Activity::own(), MSG_SIZE, CREDITS, BUF_ADDR, buf_size).unwrap();

    let n1 = start_activity("n1", n1, &n0n1_r, Some(&n1n2_s), compute_node).unwrap();
    let n2 = start_activity("n2", n2, &n1n2_r, Some(&n2n0_s), compute_node).unwrap();

    let mut chan_n0n1 = Sender::new("n0", n0n1_s.desc()).unwrap();
    let chan_n2n0 = Receiver::new("n0", n2n0_r.desc()).unwrap();

    let data = vec![0u8; buf_size as usize];

    let prof = Profiler::default().warmup(4).repeats(50);

    let res = prof.run::<TimeInstant, _>(|| {
        chan_n0n1.send_slice(&data, false, ()).unwrap();
        let _blk = chan_n2n0.receive::<(), u8>().unwrap();
    });

    wv_perf!("pipe", res);

    n1.stop().unwrap();
    n2.stop().unwrap();
    Ok(())
}

fn star(buf_size: GlobOff) -> Result<(), Error> {
    let n1 = create_activity("n1").unwrap();
    let n2 = create_activity("n2").unwrap();

    let (n0n1_s, n0n1_r) = datachan::create(&n1, MSG_SIZE, CREDITS, BUF_ADDR, buf_size).unwrap();
    let (n1n0_s, n1n0_r) =
        datachan::create(Activity::own(), MSG_SIZE, CREDITS, BUF_ADDR, buf_size).unwrap();

    let (n0n2_s, n0n2_r) = datachan::create(&n2, MSG_SIZE, CREDITS, BUF_ADDR, buf_size).unwrap();
    let (n2n0_s, n2n0_r) = datachan::create(
        Activity::own(),
        MSG_SIZE,
        CREDITS,
        BUF_ADDR + buf_size,
        buf_size,
    )
    .unwrap();

    let n1 = start_activity("n1", n1, &n0n1_r, Some(&n1n0_s), compute_node).unwrap();
    let n2 = start_activity("n2", n2, &n0n2_r, Some(&n2n0_s), compute_node).unwrap();

    let mut chan_n0n1 = Sender::new("n0", n0n1_s.desc()).unwrap();
    let mut chan_n0n2 = Sender::new("n0", n0n2_s.desc()).unwrap();
    let chan_n1n0 = Receiver::new("n0", n1n0_r.desc()).unwrap();
    let chan_n2n0 = Receiver::new("n0", n2n0_r.desc()).unwrap();

    let data = vec![0u8; buf_size as usize];

    let prof = Profiler::default().warmup(4).repeats(50);

    let res = prof.run::<TimeInstant, _>(|| {
        chan_n0n1.send_slice(&data, false, ()).unwrap();
        let blk = chan_n1n0.receive::<(), u8>().unwrap();
        chan_n0n2.send(blk, ()).unwrap();
        let _blk = chan_n2n0.receive::<(), u8>().unwrap();
    });

    wv_perf!("star", res);

    n1.stop().unwrap();
    n2.stop().unwrap();
    Ok(())
}

#[no_mangle]
pub fn main() -> Result<(), Error> {
    let args = env::args().collect::<Vec<_>>();
    let buf_size = if args.len() > 1 {
        args[1].parse().unwrap()
    }
    else {
        4096
    };

    pipeline(buf_size).unwrap();
    star(buf_size).unwrap();
    Ok(())
}
