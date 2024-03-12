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
use core::marker::PhantomData;

use crate::cfg;
use crate::chan::data::{
    self, Block, BlockReceiver, BlockSender, Receiver, ReceiverCap, ReceiverDesc, Sender,
    SenderCap, SenderDesc,
};
use crate::col::{ToString, Vec};
use crate::errors::Error;
use crate::mem::{GlobOff, VirtAddr};
use crate::serialize::{Deserialize, Serialize};
use crate::tiles::{Activity, ChildActivity};
use crate::util::math;
use crate::vec;

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct MultiSenderDesc {
    sender: Vec<SenderDesc>,
}

pub struct MultiSenderCap {
    sender: Vec<SenderCap>,
}

impl MultiSenderCap {
    pub fn new(sender: Vec<SenderCap>) -> Self {
        Self { sender }
    }

    pub fn desc(&self) -> MultiSenderDesc {
        MultiSenderDesc {
            sender: self.sender.iter().map(|s| s.desc()).collect(),
        }
    }

    pub fn desc_single(&self, idx: usize) -> MultiSenderDesc {
        MultiSenderDesc {
            sender: vec![self.sender[idx].desc()],
        }
    }

    pub fn delegate(&self, act: &ChildActivity) -> Result<(), Error> {
        for s in &self.sender {
            s.delegate(act)?;
        }
        Ok(())
    }
}

pub struct MultiSender {
    sender: Vec<Sender>,
}

impl MultiSender {
    pub fn new<S: ToString>(name: S, desc: MultiSenderDesc) -> Result<Self, Error> {
        let mut sender = Vec::with_capacity(desc.sender.len());
        let name = name.to_string();
        for d in desc.sender {
            sender.push(Sender::new(name.clone(), d)?);
        }
        Ok(Self { sender })
    }
}

impl BlockSender for MultiSender {
    type Block<'a, U, T> = MultiBlock<'a, U, T> where T: Clone + 'a;

    fn credits(&self) -> u32 {
        self.sender[0].credits()
    }

    fn block_size(&self) -> GlobOff {
        self.sender[0].block_size()
    }

    fn send<'a, U, T>(&mut self, mut mblk: Self::Block<'a, U, T>, user: U) -> Result<(), Error>
    where
        U: Clone + Debug + Serialize,
        T: Clone,
    {
        if mblk.blocks().len() > self.sender.len() {
            // number of blocks has to be divisible by number of senders
            let items_per_snd = mblk.blocks().len() / self.sender.len();
            assert_eq!(items_per_snd * self.sender.len(), mblk.blocks().len());

            let last = mblk.is_last();
            mblk.with_data(|data| -> Result<(), Error> {
                let items_per_snd = data.len() / self.sender.len();

                let mut off = 0;
                for snd in &mut self.sender {
                    snd.send_slice(&data[off..off + items_per_snd], last, user.clone())?;
                    off += items_per_snd;
                }
                Ok(())
            })?;
        }
        else {
            // same as above, but vice versa
            let snds_per_blk = self.sender.len() / mblk.blocks().len();
            assert_eq!(snds_per_blk * mblk.blocks().len(), self.sender.len());

            for blk in mblk.blocks() {
                let mut off = 0;
                let items_per_snd = blk.buf().len() / snds_per_blk;

                for snd in &mut self.sender {
                    snd.send_slice(
                        &blk.buf()[off..off + items_per_snd],
                        mblk.is_last(),
                        user.clone(),
                    )?;
                    off += items_per_snd;
                }
            }
        }
        Ok(())
    }

    fn send_slice<U, T>(&mut self, data: &[T], last: bool, user: U) -> Result<(), Error>
    where
        U: Clone + Debug + Serialize,
        T: Clone,
    {
        let block_size = data.len() / self.sender.len();
        let mut pos = 0;
        for snd in &mut self.sender {
            snd.send_slice(&data[pos..pos + block_size], last, user.clone())?;
            pos += block_size;
        }
        Ok(())
    }

    fn wait_all(&mut self) -> Result<(), Error> {
        for snd in &mut self.sender {
            snd.wait_all()?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct MultiReceiverDesc {
    receiver: Vec<ReceiverDesc>,
}

pub struct MultiReceiverCap {
    receiver: Vec<ReceiverCap>,
}

impl MultiReceiverCap {
    pub fn new(receiver: Vec<ReceiverCap>) -> Self {
        Self { receiver }
    }

    pub fn desc(&self) -> MultiReceiverDesc {
        MultiReceiverDesc {
            receiver: self.receiver.iter().map(|r| r.desc()).collect(),
        }
    }

    pub fn desc_single(&self, idx: usize) -> MultiReceiverDesc {
        MultiReceiverDesc {
            receiver: vec![self.receiver[idx].desc()],
        }
    }

    pub fn delegate(&self, act: &ChildActivity) -> Result<(), Error> {
        for r in &self.receiver {
            r.delegate(act)?;
        }
        Ok(())
    }
}

pub struct MultiReceiver {
    receiver: Vec<Receiver>,
}

impl MultiReceiver {
    pub fn new<S: ToString>(name: S, desc: MultiReceiverDesc) -> Result<Self, Error> {
        let mut receiver = Vec::with_capacity(desc.receiver.len());
        let name = name.to_string();
        for d in desc.receiver {
            receiver.push(Receiver::new(name.clone(), d)?);
        }

        Ok(Self { receiver })
    }
}

impl BlockReceiver for MultiReceiver {
    type Block<'a, U, T> = MultiBlock<'a, U, T> where T: Clone + 'a;

    fn buf_range(&self) -> (VirtAddr, GlobOff) {
        self.receiver[0].buf_range()
    }

    fn buf_size(&self) -> GlobOff {
        self.receiver[0].buf_size()
    }

    fn receive<'a, U, T>(&'a self) -> Result<Self::Block<'a, U, T>, Error>
    where
        U: Serialize + Deserialize<'static> + Debug,
        T: Clone + 'a,
    {
        let mut blocks = Vec::with_capacity(self.receiver.len());
        for r in &self.receiver {
            match r.receive() {
                Ok(b) => {
                    blocks.push(b);
                },
                Err(e) => return Err(e),
            }
        }
        Ok(MultiBlock { blocks })
    }

    fn iter<'a, U, T>(&'a self) -> impl Iterator<Item = Self::Block<'a, U, T>>
    where
        U: Serialize + Deserialize<'static> + Debug,
        T: Clone + 'a,
    {
        MultiBlockIterator {
            recv: self,
            seen_last: false,
            phantom: PhantomData::default(),
        }
    }
}

pub struct MultiBlock<'a, U, T> {
    blocks: Vec<Block<'a, U, T>>,
}

impl<'a, U, T: Clone> MultiBlock<'a, U, T> {
    pub fn blocks(&self) -> &[Block<'a, U, T>] {
        &self.blocks
    }

    pub fn blocks_mut(&mut self) -> &mut [Block<'a, U, T>] {
        &mut self.blocks
    }

    pub fn with_data<F, R>(&mut self, func: F) -> R
    where
        F: FnOnce(&mut [T]) -> R,
    {
        if self.blocks.len() == 1 {
            func(self.blocks[0].buf_mut())
        }
        else {
            func(&mut self.to_vec())
        }
    }

    pub fn to_vec(&self) -> Vec<T> {
        let cap = self.blocks.iter().fold(0, |sum, b| sum + b.buf().len());
        self.blocks
            .iter()
            .fold(Vec::with_capacity(cap), |mut v, b| {
                v.extend_from_slice(b.buf());
                v
            })
    }

    pub fn is_last(&self) -> bool {
        self.blocks[0].is_last()
    }
}

pub struct MultiBlockIterator<'a, U, T> {
    recv: &'a MultiReceiver,
    seen_last: bool,
    phantom: PhantomData<(U, T)>,
}

impl<'a, U: Serialize + Deserialize<'static> + Debug, T: Clone + 'a> Iterator
    for MultiBlockIterator<'a, U, T>
{
    type Item = MultiBlock<'a, U, T>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.seen_last {
            return None;
        }

        let mblock = self.recv.receive().ok()?;
        self.seen_last = mblock.is_last();
        Some(mblock)
    }
}

pub fn create_single(
    recv: &Activity,
    msg_size: usize,
    slots: u32,
    buf_addr: VirtAddr,
    buf_size: GlobOff,
) -> Result<(MultiSenderCap, MultiReceiverCap), Error> {
    let (send, recv) = data::create(recv, msg_size, slots, buf_addr, buf_size)?;
    Ok((
        MultiSenderCap::new(vec![send]),
        MultiReceiverCap::new(vec![recv]),
    ))
}

pub fn create_fanout<'a, I>(
    recvs: I,
    msg_size: usize,
    slots: u32,
    mut buf_addr: VirtAddr,
    buf_size: GlobOff,
) -> Result<(MultiSenderCap, MultiReceiverCap), Error>
where
    I: Iterator<Item = &'a Activity>,
{
    let mut sender = Vec::new();
    let mut receiver = Vec::new();
    for r in recvs {
        let (send, recv) = data::create(r, msg_size, slots, buf_addr, buf_size)?;
        sender.push(send);
        receiver.push(recv);
        buf_addr += math::round_up(buf_size as usize * slots as usize, cfg::PAGE_SIZE);
    }
    Ok((MultiSenderCap::new(sender), MultiReceiverCap::new(receiver)))
}

pub fn create_fanin(
    recv: &Activity,
    msg_size: usize,
    slots: u32,
    mut buf_addr: VirtAddr,
    buf_size: GlobOff,
    fanin: usize,
) -> Result<(MultiSenderCap, MultiReceiverCap), Error> {
    let mut sender = Vec::new();
    let mut receiver = Vec::new();
    for _ in 0..fanin {
        let (send, recv) = data::create(recv, msg_size, slots, buf_addr, buf_size)?;
        sender.push(send);
        receiver.push(recv);
        buf_addr += math::round_up(buf_size as usize * slots as usize, cfg::PAGE_SIZE);
    }
    Ok((MultiSenderCap::new(sender), MultiReceiverCap::new(receiver)))
}
