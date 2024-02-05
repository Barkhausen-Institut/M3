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
use core::ops::Deref;

use m3::chan::data::{self as datachan, BlockReceiver, BlockSender};
use m3::chan::multidata::{
    self as mdatachan, MultiReceiver, MultiReceiverCap, MultiReceiverDesc, MultiSender,
    MultiSenderCap, MultiSenderDesc,
};
use m3::col::{String, ToString, Vec};
use m3::errors::{Code, Error};
use m3::io::LogFlags;
use m3::mem::GlobOff;
use m3::serialize::{Deserialize, Serialize};
use m3::tiles::{Activity, ChildActivity, RunningActivity, RunningProgramActivity};
use m3::time::{CycleDuration, CycleInstant, Duration};
use m3::{cfg, format, log, println, vec};

use crate::utils;

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "m3::serde")]
struct NodeConfig {
    name: String,
    comp_time: CycleDuration,
    chunk_size: usize,
    recv: MultiReceiverDesc,
    send: Option<MultiSenderDesc>,
}

fn start_activity<S: ToString>(
    name: S,
    mut act: ChildActivity,
    recv: (&MultiReceiverCap, Option<usize>),
    send: Option<(&MultiSenderCap, Option<usize>)>,
    comp_time: CycleDuration,
    chunk_size: usize,
) -> Result<RunningProgramActivity, Error> {
    recv.0.delegate(&act)?;
    if let Some(send) = send {
        send.0.delegate(&act)?;
    }

    let mut dst = act.data_sink();
    dst.push(NodeConfig {
        name: name.to_string(),
        comp_time,
        chunk_size,
        recv: match recv {
            (cap, Some(idx)) => cap.desc_single(idx),
            (cap, None) => cap.desc(),
        },
        send: send.map(|s| match s {
            (cap, Some(idx)) => cap.desc_single(idx),
            (cap, None) => cap.desc(),
        }),
    });

    act.run(compute_node)
}

fn compute_node() -> Result<(), Error> {
    let mut src = Activity::own().data_source();
    let cfg: NodeConfig = src.pop().unwrap();

    let recv = MultiReceiver::new(cfg.name.clone(), cfg.recv).expect("data chan receiver");
    let mut send = cfg
        .send
        .map(|s| MultiSender::new(cfg.name.clone(), s).expect("data chan sender"));

    log!(LogFlags::Debug, "{}: starting", cfg.name);

    for mut blk in recv.iter::<(), f32>() {
        let last = blk.is_last();
        blk.with_data(|data| {
            for _chk in data.chunks(cfg.chunk_size) {
                utils::compute_for(&cfg.name, cfg.comp_time);
            }

            if let Some(send) = send.as_mut() {
                send.send_slice(data, last, ()).expect("send");
            }
        });
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

    let buf_addr = utils::buffer_addr();

    let n1 = utils::create_activity("n1").expect("create n1");
    let n2s = (0..4)
        .map(|i| utils::create_activity(format!("n2_{}", i)).expect("create ns"))
        .collect::<Vec<_>>();
    let n3 = utils::create_activity("n3").expect("create n3");

    let (n0n1_s, n0n1_r) = mdatachan::create_single(&n1, MSG_SIZE, CREDITS, buf_addr, BUF_SIZE)
        .expect("n0->n1 channel");
    let (n1n2s_s, n1n2s_r) = mdatachan::create_fanout(
        n2s.iter().map(|a| a.deref()),
        MSG_SIZE,
        CREDITS,
        buf_addr,
        BUF_SIZE,
    )
    .expect("n1->n2s channel");
    let (n2sn3_s, n2sn3_r) =
        mdatachan::create_fanin(&n3, MSG_SIZE, CREDITS, buf_addr, BUF_SIZE, n2s.len())
            .expect("n2s->n3 channel");
    let (n3n0_s, n3n0_r) =
        mdatachan::create_single(Activity::own(), MSG_SIZE, CREDITS, buf_addr, BUF_SIZE)
            .expect("n3->n0 channel");

    let n1 = start_activity(
        "n1",
        n1,
        (&n0n1_r, None),
        Some((&n1n2s_s, None)),
        CycleDuration::from_raw(CHUNK_TIME / 2),
        CHUNK_SIZE,
    )
    .expect("start n1");

    let n2s = n2s
        .into_iter()
        .enumerate()
        .map(|(i, a)| {
            start_activity(
                format!("n2_{}", i),
                a,
                (&n1n2s_r, Some(i)),
                Some((&n2sn3_s, Some(i))),
                CycleDuration::from_raw(CHUNK_TIME),
                CHUNK_SIZE / 4,
            )
            .expect("start n2s")
        })
        .collect::<Vec<_>>();

    let n3 = start_activity(
        "n3",
        n3,
        (&n2sn3_r, None),
        Some((&n3n0_s, None)),
        CycleDuration::from_raw(CHUNK_TIME / 2),
        CHUNK_SIZE,
    )
    .expect("start n3");

    let data = vec![0.0f32; BUF_SIZE as usize * 4];

    let mut chan_n0n1 = MultiSender::new("n0", n0n1_s.desc()).expect("chan_n0n1");
    let mut chan_n3n0 = MultiReceiver::new("n0", n3n0_r.desc()).expect("chan_n3n0");

    let start = CycleInstant::now();

    datachan::pass_through(&mut chan_n0n1, &mut chan_n3n0, &data, true, (), |blk| {
        let total = blk.blocks().iter().fold(0, |acc, b| acc + b.buf().len());
        log!(
            LogFlags::Debug,
            "Got {} bytes in {} blocks",
            total,
            blk.blocks().len()
        );
    })
    .expect("pass through");

    let end = CycleInstant::now();
    println!("Total duration: {:?}", end.duration_since(start));

    assert_eq!(n1.wait(), Ok(Code::Success));
    for n in n2s {
        assert_eq!(n.wait(), Ok(Code::Success));
    }
    assert_eq!(n3.wait(), Ok(Code::Success));

    Ok(())
}
