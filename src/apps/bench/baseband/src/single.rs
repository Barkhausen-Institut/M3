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

use core::fmt::Debug;

use m3::chan::data::{
    self as datachan, BlockReceiver, BlockSender, Receiver, ReceiverCap, ReceiverDesc, Sender,
    SenderCap, SenderDesc,
};
use m3::col::{String, ToString};
use m3::errors::{Code, Error};
use m3::io::LogFlags;
use m3::mem::{GlobOff, VirtAddr};
use m3::serialize::{Deserialize, Serialize};
use m3::tiles::{
    Activity, ActivityArgs, ChildActivity, RunningActivity, RunningProgramActivity, Tile,
};
use m3::time::{CycleDuration, CycleInstant, Duration};
use m3::{cfg, log, println, vec};

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "m3::serde")]
struct NodeConfig {
    name: String,
    comp_time: CycleDuration,
    chunk_size: usize,
    recv: ReceiverDesc,
    send: Option<SenderDesc>,
}

fn start_activity<S: ToString>(
    name: S,
    mut act: ChildActivity,
    recv: &ReceiverCap,
    send: Option<&SenderCap>,
    comp_time: CycleDuration,
    chunk_size: usize,
) -> Result<RunningProgramActivity, Error> {
    recv.delegate(&act)?;
    if let Some(send) = send {
        send.delegate(&act)?;
    }

    let mut dst = act.data_sink();
    dst.push(NodeConfig {
        name: name.to_string(),
        comp_time,
        chunk_size,
        recv: recv.desc(),
        send: send.map(|s| s.desc()),
    });

    act.run(compute_node)
}

fn create_activity<S: AsRef<str>>(name: S) -> Result<ChildActivity, Error> {
    let tile = Tile::get("compat")?;
    ChildActivity::new_with(tile, ActivityArgs::new(name.as_ref()))
}

fn compute_for(name: &str, duration: CycleDuration) {
    log!(LogFlags::Debug, "{}: computing for {:?}", name, duration);

    let end = CycleInstant::now().as_cycles() + duration.as_raw();
    while CycleInstant::now().as_cycles() < end {}
}

fn compute_node() -> Result<(), Error> {
    let mut src = Activity::own().data_source();
    let cfg: NodeConfig = src.pop().unwrap();

    let recv = Receiver::new(cfg.name.clone(), cfg.recv).expect("data chan receiver");
    let mut send = cfg
        .send
        .map(|s| Sender::new(cfg.name.clone(), s).expect("data chan sender"));

    log!(LogFlags::Debug, "{}: starting", cfg.name);

    for blk in recv.iter::<(), f32>() {
        for _chk in blk.buf().chunks(cfg.chunk_size) {
            compute_for(&cfg.name, cfg.comp_time);
        }

        if let Some(send) = send.as_mut() {
            send.send(blk, ()).expect("send");
        }
    }

    log!(LogFlags::Debug, "{}: finished", cfg.name);

    Ok(())
}

// note on measurements: when we push the data directly into the cache and the data is sufficiently
// small, our data is always warm. we might therefore want to take that into account when measuring
// on Linux. Like, measure it once "normally" and again with a few repeats to get the time with
// warm caches. For Linux, we then use the "normal time" and for M³ the "warm time".

pub fn run() -> Result<(), Error> {
    const MSG_SIZE: usize = 128;
    const CREDITS: u32 = 4;
    const CHUNK_TIME: u64 = 100000;
    const CHUNK_SIZE: usize = 1024;
    const BUF_SIZE: GlobOff = cfg::PAGE_SIZE as GlobOff;

    // TODO that's a bit of guess work here; at some point we might want to have an abstraction in
    // libm3 that manages our address space or so.
    let tile_desc = Activity::own().tile_desc();
    let buf_addr = if tile_desc.has_virtmem() {
        VirtAddr::new(0x3000_0000)
    }
    else {
        VirtAddr::from(tile_desc.mem_size() / 2)
    };

    let n1 = create_activity("n1").expect("create n1");
    let n2 = create_activity("n2").expect("create n2");

    let (n0n1_s, n0n1_r) =
        datachan::create(&n1, MSG_SIZE, CREDITS, buf_addr, BUF_SIZE).expect("n0->n1 channel");
    let (n1n2_s, n1n2_r) =
        datachan::create(&n2, MSG_SIZE, CREDITS, buf_addr, BUF_SIZE).expect("n1->n2 channel");
    let (n2n0_s, n2n0_r) = datachan::create(Activity::own(), MSG_SIZE, CREDITS, buf_addr, BUF_SIZE)
        .expect("n2->n0 channel");

    let n1 = start_activity(
        "n1",
        n1,
        &n0n1_r,
        Some(&n1n2_s),
        CycleDuration::from_raw(CHUNK_TIME),
        CHUNK_SIZE,
    )
    .expect("start n1");

    let n2 = start_activity(
        "n2",
        n2,
        &n1n2_r,
        Some(&n2n0_s),
        CycleDuration::from_raw(CHUNK_TIME),
        CHUNK_SIZE,
    )
    .expect("start n2");

    let data = vec![0.0f32; BUF_SIZE as usize * 4];

    let mut chan_n0n1 = Sender::new("n0", n0n1_s.desc()).expect("chan_n0n1");
    let mut chan_n3n0 = Receiver::new("n0", n2n0_r.desc()).expect("chan_n2n0");

    let start = CycleInstant::now();

    datachan::pass_through(&mut chan_n0n1, &mut chan_n3n0, &data, true, (), |blk| {
        log!(LogFlags::Debug, "Got {} bytes", blk.buf().len());
    })
    .expect("pass through");

    let end = CycleInstant::now();
    println!("Total duration: {:?}", end.duration_since(start));

    assert_eq!(n1.wait(), Ok(Code::Success));
    assert_eq!(n2.wait(), Ok(Code::Success));

    Ok(())
}
