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
    cfg,
    chan::data::{
        self as datachan, BlockReceiver, BlockSender, Receiver, ReceiverCap, ReceiverDesc, Sender,
        SenderCap, SenderDesc,
    },
    col::{String, ToString, Vec},
    env,
    errors::Error,
    io::LogFlags,
    log,
    mem::{AlignedBuf, GlobOff, VirtAddr},
    serialize::{Deserialize, Serialize},
    tiles::{Activity, ActivityArgs, ChildActivity, RunningActivity, RunningProgramActivity, Tile},
    time::{Profiler, TimeInstant},
    util::math,
    wv_perf,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "m3::serde")]
struct NodeConfig {
    name: String,
    recv: ReceiverDesc,
    send: Option<SenderDesc>,
}

fn create_activity<S: AsRef<str>>(name: S, tile_type: S) -> Result<ChildActivity, Error> {
    let tile = Tile::get(tile_type.as_ref())?;
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

static BUF: AlignedBuf<{ 32 * 1024 }> = AlignedBuf::new_zeroed();

fn server_dist(buf_size: GlobOff) -> Result<(), Error> {
    let n1 = create_activity("n1", "effi").unwrap();
    let n2 = create_activity("n2", "effi").unwrap();

    let (n0n1_s, n0n1_r) = datachan::create(&n1, MSG_SIZE, CREDITS, BUF_ADDR, buf_size).unwrap();
    let (n1n2_s, n1n2_r) = datachan::create(&n2, MSG_SIZE, CREDITS, BUF_ADDR, buf_size).unwrap();
    let (n2n0_s, n2n0_r) =
        datachan::create(Activity::own(), MSG_SIZE, CREDITS, BUF_ADDR, buf_size).unwrap();

    let n1 = start_activity("n1", n1, &n0n1_r, Some(&n1n2_s), compute_node).unwrap();
    let n2 = start_activity("n2", n2, &n1n2_r, Some(&n2n0_s), compute_node).unwrap();

    let mut chan_n0n1 = Sender::new("n0", n0n1_s.desc()).unwrap();
    let chan_n2n0 = Receiver::new("n0", n2n0_r.desc()).unwrap();

    let prof = Profiler::default().warmup(4).repeats(50);

    let res = prof.run::<TimeInstant, _>(|| {
        chan_n0n1
            .send_slice(&BUF[0..buf_size as usize], false, ())
            .unwrap();
        let _blk = chan_n2n0.receive::<(), u8>().unwrap();
    });

    wv_perf!("srv-dist", res);

    n1.stop().unwrap();
    n2.stop().unwrap();
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "m3::serde")]
struct CPUConfig {
    name: String,
    recv: ReceiverDesc,
    send: SenderDesc,
    chan_n1: (SenderDesc, ReceiverDesc),
    chan_n2: (SenderDesc, ReceiverDesc),
}

fn start_cpu<S: ToString>(
    name: S,
    mut act: ChildActivity,
    recv: &ReceiverCap,
    send: &SenderCap,
    chan_n1: (&SenderCap, &ReceiverCap),
    chan_n2: (&SenderCap, &ReceiverCap),
) -> Result<RunningProgramActivity, Error> {
    recv.delegate(&act)?;
    send.delegate(&act)?;
    chan_n1.0.delegate(&act)?;
    chan_n1.1.delegate(&act)?;
    chan_n2.0.delegate(&act)?;
    chan_n2.1.delegate(&act)?;

    let mut dst = act.data_sink();
    dst.push(CPUConfig {
        name: name.to_string(),
        recv: recv.desc(),
        send: send.desc(),
        chan_n1: (chan_n1.0.desc(), chan_n1.1.desc()),
        chan_n2: (chan_n2.0.desc(), chan_n2.1.desc()),
    });

    act.run(server_cpu)
}

fn server_cpu() -> Result<(), Error> {
    let mut src = Activity::own().data_source();
    let cfg: CPUConfig = src.pop().unwrap();
    // TODO the print is a workaround for the gem5 bug regarding the movss instruction :)
    log!(LogFlags::Info, "got {:?}", cfg);

    let mut chan_n0n1 = Sender::new(cfg.name.clone(), cfg.chan_n1.0).unwrap();
    let mut chan_n0n2 = Sender::new(cfg.name.clone(), cfg.chan_n2.0).unwrap();
    let chan_n1n0 = Receiver::new(cfg.name.clone(), cfg.chan_n1.1).unwrap();
    let chan_n2n0 = Receiver::new(cfg.name.clone(), cfg.chan_n2.1).unwrap();

    let recv = Receiver::new(cfg.name.clone(), cfg.recv).unwrap();
    let mut send = Sender::new(cfg.name.clone(), cfg.send).unwrap();

    for blk in recv.iter::<(), u8>() {
        chan_n0n1.send(blk, ()).unwrap();

        let n1blk = chan_n1n0.receive::<(), u8>().unwrap();
        chan_n0n2.send(n1blk, ()).unwrap();

        let n2blk = chan_n2n0.receive::<(), u8>().unwrap();
        send.send(n2blk, ()).unwrap();
    }

    Ok(())
}

fn server_central(buf_size: GlobOff) -> Result<(), Error> {
    let cpu = create_activity("cpu", "perf").unwrap();
    let n1 = create_activity("n1", "effi").unwrap();
    let n2 = create_activity("n2", "effi").unwrap();

    let (n0cp_s, n0cp_r) = datachan::create(&cpu, MSG_SIZE, CREDITS, BUF_ADDR, buf_size).unwrap();

    let (cpn1_s, cpn1_r) = datachan::create(&n1, MSG_SIZE, CREDITS, BUF_ADDR, buf_size).unwrap();
    let (n1cp_s, n1cp_r) = datachan::create(
        &cpu,
        MSG_SIZE,
        CREDITS,
        BUF_ADDR + math::round_up(buf_size, cfg::PAGE_SIZE as GlobOff),
        buf_size,
    )
    .unwrap();

    let (cpn2_s, cpn2_r) = datachan::create(&n2, MSG_SIZE, CREDITS, BUF_ADDR, buf_size).unwrap();
    let (n2cp_s, n2cp_r) = datachan::create(
        &cpu,
        MSG_SIZE,
        CREDITS,
        BUF_ADDR + math::round_up(buf_size, cfg::PAGE_SIZE as GlobOff) * 2,
        buf_size,
    )
    .unwrap();

    let (cpn0_s, cpn0_r) =
        datachan::create(Activity::own(), MSG_SIZE, CREDITS, BUF_ADDR, buf_size).unwrap();

    let cpu = start_cpu(
        "cpu",
        cpu,
        &n0cp_r,
        &cpn0_s,
        (&cpn1_s, &n1cp_r),
        (&cpn2_s, &n2cp_r),
    )
    .unwrap();
    let n1 = start_activity("n1", n1, &cpn1_r, Some(&n1cp_s), compute_node).unwrap();
    let n2 = start_activity("n2", n2, &cpn2_r, Some(&n2cp_s), compute_node).unwrap();

    let mut chan_n0cp = Sender::new("n0", n0cp_s.desc()).unwrap();
    let chan_cpn0 = Receiver::new("n0", cpn0_r.desc()).unwrap();

    let prof = Profiler::default().warmup(4).repeats(50);

    let res = prof.run::<TimeInstant, _>(|| {
        chan_n0cp
            .send_slice(&BUF[0..buf_size as usize], false, ())
            .unwrap();
        let _blk = chan_cpn0.receive::<(), u8>().unwrap();
    });

    wv_perf!("srv-central", res);

    cpu.stop().unwrap();
    n1.stop().unwrap();
    n2.stop().unwrap();
    Ok(())
}

fn client(buf_size: GlobOff) -> Result<(), Error> {
    let n1 = create_activity("n1", "effi").unwrap();
    let n2 = create_activity("n2", "effi").unwrap();

    let (n0n1_s, n0n1_r) = datachan::create(&n1, MSG_SIZE, CREDITS, BUF_ADDR, buf_size).unwrap();
    let (n1n0_s, n1n0_r) =
        datachan::create(Activity::own(), MSG_SIZE, CREDITS, BUF_ADDR, buf_size).unwrap();

    let (n0n2_s, n0n2_r) = datachan::create(&n2, MSG_SIZE, CREDITS, BUF_ADDR, buf_size).unwrap();
    let (n2n0_s, n2n0_r) = datachan::create(
        Activity::own(),
        MSG_SIZE,
        CREDITS,
        BUF_ADDR + math::round_up(buf_size, cfg::PAGE_SIZE as GlobOff),
        buf_size,
    )
    .unwrap();

    let n1 = start_activity("n1", n1, &n0n1_r, Some(&n1n0_s), compute_node).unwrap();
    let n2 = start_activity("n2", n2, &n0n2_r, Some(&n2n0_s), compute_node).unwrap();

    let mut chan_n0n1 = Sender::new("n0", n0n1_s.desc()).unwrap();
    let mut chan_n0n2 = Sender::new("n0", n0n2_s.desc()).unwrap();
    let chan_n1n0 = Receiver::new("n0", n1n0_r.desc()).unwrap();
    let chan_n2n0 = Receiver::new("n0", n2n0_r.desc()).unwrap();

    let prof = Profiler::default().warmup(4).repeats(50);

    let res = prof.run::<TimeInstant, _>(|| {
        chan_n0n1
            .send_slice(&BUF[0..buf_size as usize], false, ())
            .unwrap();
        let blk = chan_n1n0.receive::<(), u8>().unwrap();
        chan_n0n2.send(blk, ()).unwrap();
        let _blk = chan_n2n0.receive::<(), u8>().unwrap();
    });

    wv_perf!("cli", res);

    n1.stop().unwrap();
    n2.stop().unwrap();
    Ok(())
}

#[no_mangle]
pub fn main() -> Result<(), Error> {
    let args = env::args().collect::<Vec<_>>();

    let mode = args[1];
    let buf_size = if args.len() > 2 {
        args[2].parse().unwrap()
    }
    else {
        4096
    };

    match mode {
        "srv-dist" => server_dist(buf_size).unwrap(),
        "srv-central" => server_central(buf_size).unwrap(),
        "cli" => client(buf_size).unwrap(),
        _ => panic!("unknown mode {}", mode),
    }

    Ok(())
}
