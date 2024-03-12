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

use base::build_vmsg;

use crate::cap::Selector;
use crate::cfg;
use crate::col::{String, ToString};
use crate::com::{
    recv_msg, GateIStream, MGateArgs, MemCap, MemGate, RecvCap, RecvGate, SGateArgs, SendCap,
    SendGate,
};
use crate::errors::{Code, Error};
use crate::io::LogFlags;
use crate::kif::Perm;
use crate::mem::{size_of, size_of_val, GlobOff, MsgBuf, VirtAddr};
use crate::serialize::{Deserialize, Serialize};
use crate::tiles::{Activity, ChildActivity};
use crate::util::math;
use crate::{log, vec};

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
struct Request<U> {
    off: usize,
    size: usize,
    last: bool,
    user: U,
}

impl<U> Request<U> {
    fn new(off: usize, size: usize, last: bool, user: U) -> Self {
        Self {
            off,
            size,
            last,
            user,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct SenderDesc {
    send: Selector,
    reply: Selector,
    buf: Selector,
    blk_size: GlobOff,
    buf_dist: GlobOff,
    reply_size: usize,
    credits: u32,
}

pub struct SenderCap {
    send: SendCap,
    reply: RecvCap,
    buf: MemCap,
    blk_size: GlobOff,
    buf_dist: GlobOff,
    reply_size: usize,
    credits: u32,
}

impl SenderCap {
    pub fn new(
        recv: &ReceiverCap,
        blk_size: GlobOff,
        buf_dist: GlobOff,
        reply_size: usize,
        credits: u32,
    ) -> Result<Self, Error> {
        let reply = RecvCap::new(
            math::next_log2(reply_size * credits as usize),
            math::next_log2(reply_size),
        )?;
        let send = SendCap::new_with(SGateArgs::new(&recv.recv).credits(credits))?;
        let buf = MemCap::new_bind(recv.buf.buf.sel());
        Ok(Self {
            send,
            reply,
            buf,
            blk_size,
            buf_dist,
            reply_size,
            credits,
        })
    }

    pub fn desc(&self) -> SenderDesc {
        SenderDesc {
            send: self.send.sel(),
            reply: self.reply.sel(),
            buf: self.buf.sel(),
            blk_size: self.blk_size,
            buf_dist: self.buf_dist,
            reply_size: self.reply_size,
            credits: self.credits,
        }
    }

    pub fn delegate(&self, act: &ChildActivity) -> Result<(), Error> {
        act.delegate_obj(self.send.sel())?;
        act.delegate_obj(self.reply.sel())?;
        act.delegate_obj(self.buf.sel())
    }
}

pub trait BlockSender {
    type Block<'a, U, T>
    where
        T: Clone + 'a;

    fn credits(&self) -> u32;
    fn block_size(&self) -> GlobOff;

    fn wait_all(&mut self) -> Result<(), Error>;

    fn send<U: Debug + Clone + Serialize, T: Clone>(
        &mut self,
        blk: Self::Block<'_, U, T>,
        user: U,
    ) -> Result<(), Error>;

    fn send_slice<U: Debug + Clone + Serialize, T: Clone>(
        &mut self,
        data: &[T],
        last: bool,
        user: U,
    ) -> Result<(), Error>;
}

pub struct Sender {
    name: String,
    send: SendGate,
    reply: RecvGate,
    buf: MemGate,
    msg: MsgBuf,
    credits: u32,
    idx: usize,
    buf_dist: GlobOff,
    blk_size: GlobOff,
    in_flight: usize,
}

impl Sender {
    pub fn new<S: ToString>(name: S, desc: SenderDesc) -> Result<Self, Error> {
        let send = SendGate::new_bind(desc.send)?;
        let reply = RecvGate::new_bind(desc.reply)?;
        let buf = MemGate::new_bind(desc.buf)?;

        let mut msg = MsgBuf::new();
        msg.set(vec![0u8; desc.reply_size]);

        log!(
            LogFlags::LibDataChan,
            "{}: using buffer=({}, {}), dist={}",
            name.to_string(),
            buf.region().unwrap().0,
            desc.blk_size * desc.credits as GlobOff,
            desc.buf_dist,
        );

        Ok(Self {
            name: name.to_string(),
            send,
            reply,
            buf,
            msg,
            credits: desc.credits,
            idx: 0,
            buf_dist: desc.buf_dist,
            blk_size: desc.blk_size,
            in_flight: 0,
        })
    }

    fn fetch_reply(&mut self) -> Result<(), Error> {
        log!(
            LogFlags::LibDataChan,
            "{}: waiting for reply ...",
            self.name
        );
        let _m = recv_msg(&self.reply)?;
        log!(LogFlags::LibDataChan, "{}: got reply", self.name);
        self.in_flight -= 1;
        Ok(())
    }
}

impl BlockSender for Sender {
    type Block<'a, U, T> = Block<'a, U, T> where T: Clone + 'a;

    fn credits(&self) -> u32 {
        self.credits
    }

    fn block_size(&self) -> GlobOff {
        self.blk_size
    }

    fn wait_all(&mut self) -> Result<(), Error> {
        while self.in_flight > 0 {
            self.fetch_reply()?;
        }
        Ok(())
    }

    fn send<U, T>(&mut self, blk: Self::Block<'_, U, T>, user: U) -> Result<(), Error>
    where
        U: Debug + Clone + Serialize,
        T: Clone,
    {
        self.send_slice(blk.buf(), blk.is_last(), user)
    }

    fn send_slice<U, T>(&mut self, data: &[T], last: bool, user: U) -> Result<(), Error>
    where
        U: Debug + Clone + Serialize,
        T: Clone,
    {
        // make sure that there is at least space for one reply to the message we are about
        // to send. also, don't write to the buffer if we have no credits, because we might
        // otherwise overwrite the data at the receiver while it's still processed.
        if self.reply.has_msgs() || !self.send.can_send()? {
            self.fetch_reply()?;
        }

        let size = size_of_val(data);
        let off = self.idx * self.buf_dist as usize;
        log!(
            LogFlags::LibDataChan,
            "{}: writing to {}..{} (abs={})",
            self.name,
            off,
            off + size - 1,
            self.buf.region().unwrap().0 + off as GlobOff
        );
        self.buf.write(data, off as GlobOff)?;
        self.idx = (self.idx + 1) % (self.credits as usize);

        let req = Request::new(off, size, last, user);
        log!(LogFlags::LibDataChan, "{}: sending {:?}", self.name, &req);
        build_vmsg!(self.msg, req);

        self.send.send(&self.msg, &self.reply)?;
        self.in_flight += 1;
        Ok(())
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        self.wait_all().ok();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct ReceiverDesc {
    buf_range: (VirtAddr, GlobOff),
    recv: Selector,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(crate = "base::serde")]
pub struct BufferDesc {
    range: (VirtAddr, GlobOff),
}

impl BufferDesc {
    pub fn range(&self) -> (VirtAddr, GlobOff) {
        self.range
    }
}

pub struct Buffer {
    _pmem: Option<MemCap>,
    buf: MemCap,
    range: (VirtAddr, GlobOff),
    unmap: bool,
}

impl Buffer {
    pub fn new(act: &Activity, buf_addr: VirtAddr, buf_size: GlobOff) -> Result<Self, Error> {
        let map_size = math::round_up(buf_size, cfg::PAGE_SIZE as GlobOff);

        let pmem = if let Some(pg) = act.pager() {
            let pmem = MemCap::new_with(MGateArgs::new(map_size, Perm::RW))?;
            pg.map_mem(buf_addr, pmem.sel(), map_size as usize, Perm::RW)?;
            // fault the region in; the pager does this in one go since it's coming from a single
            // memory capability.
            pg.pagefault(buf_addr, Perm::W)?;
            Some(pmem)
        }
        else {
            None
        };

        let buf = MemCap::new_foreign(act.sel(), buf_addr, map_size, Perm::RW)?;
        Ok(Self {
            _pmem: pmem,
            buf,
            range: (buf_addr, buf_size),
            unmap: act.pager.is_some() && act.id() == Activity::own().id(),
        })
    }

    pub fn desc(&self) -> BufferDesc {
        BufferDesc { range: self.range }
    }

    pub fn derive(&self, offset: GlobOff) -> Result<Self, Error> {
        let buf = self.buf.derive(offset, self.range.1 - offset, Perm::RW)?;
        Ok(Self {
            _pmem: None,
            buf,
            range: (self.range.0 + offset, self.range.1 - offset),
            unmap: false,
        })
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        if self.unmap {
            Activity::own().pager().unwrap().unmap(self.range.0).ok();
        }
    }
}

pub struct ReceiverCap {
    recv: RecvCap,
    buf: Buffer,
}

impl ReceiverCap {
    pub fn new(msg_size: usize, slots: u32, buf: Buffer) -> Result<Self, Error> {
        let recv = RecvCap::new(
            math::next_log2(msg_size * slots as usize),
            math::next_log2(msg_size),
        )?;
        Ok(Self { recv, buf })
    }

    pub fn desc(&self) -> ReceiverDesc {
        ReceiverDesc {
            buf_range: self.buf.range,
            recv: self.recv.sel(),
        }
    }

    pub fn buf_desc(&self) -> BufferDesc {
        BufferDesc {
            range: self.buf.range,
        }
    }

    pub fn delegate(&self, act: &ChildActivity) -> Result<(), Error> {
        act.delegate_obj(self.recv.sel())
    }
}

pub trait BlockReceiver {
    type Block<'a, U, T>
    where
        Self: 'a,
        T: Clone + 'a;

    fn buf_range(&self) -> (VirtAddr, GlobOff);
    fn buf_size(&self) -> GlobOff;

    fn receive<'a, U, T>(&'a self) -> Result<Self::Block<'a, U, T>, Error>
    where
        U: Serialize + Deserialize<'static> + Debug,
        T: Clone + 'a;

    fn iter<'a, U, T>(&'a self) -> impl Iterator<Item = Self::Block<'a, U, T>>
    where
        U: Serialize + Deserialize<'static> + Debug,
        T: Clone + 'a;
}

pub struct Receiver {
    name: String,
    recv: RecvGate,
    buf_range: (VirtAddr, GlobOff),
}

impl Receiver {
    pub fn new<S: ToString>(name: S, desc: ReceiverDesc) -> Result<Self, Error> {
        let recv = RecvGate::new_bind(desc.recv)?;
        Ok(Self {
            name: name.to_string(),
            buf_range: desc.buf_range,
            recv,
        })
    }
}

impl BlockReceiver for Receiver {
    type Block<'a, U, T> = Block<'a, U, T> where T: Clone + 'a;

    fn buf_range(&self) -> (VirtAddr, GlobOff) {
        self.buf_range
    }

    fn buf_size(&self) -> GlobOff {
        self.buf_range().1
    }

    fn receive<'a, U, T>(&'a self) -> Result<Self::Block<'a, U, T>, Error>
    where
        U: Serialize + Deserialize<'static> + Debug,
        T: Clone + 'a,
    {
        log!(
            LogFlags::LibDataChan,
            "{}: waiting for request ...",
            self.name
        );
        let mut is = recv_msg(&self.recv)?;

        let req: Request<U> = is.pop().unwrap();
        log!(LogFlags::LibDataChan, "{}: received {:?}", self.name, &req);

        // safety: we assume here that ReceiverDesc actually comes from a ReceiverCap that was
        // created for our activity. if so, we know that this region exists and is writable
        let all_buf = unsafe {
            core::slice::from_raw_parts_mut(
                self.buf_range.0.as_mut_ptr::<T>(),
                self.buf_range.1 as usize / size_of::<T>(),
            )
        };
        let ioff = req.off / size_of::<T>();
        let isize = req.size / size_of::<T>();
        let buf = &mut all_buf[ioff..ioff + isize];

        Ok(Block {
            is,
            name: &self.name,
            buf,
            last: req.last,
            user: req.user,
        })
    }

    fn iter<'a, U, T>(&'a self) -> impl Iterator<Item = Self::Block<'a, U, T>>
    where
        U: Serialize + Deserialize<'static> + Debug,
        T: Clone + 'a,
    {
        BlockIterator {
            recv: self,
            seen_last: false,
            phantom: PhantomData,
        }
    }
}

pub struct Block<'a, U, T> {
    buf: &'a mut [T],
    last: bool,
    user: U,
    name: &'a str,
    is: GateIStream<'a>,
}

impl<'a, U, T> Block<'a, U, T> {
    pub fn buf(&self) -> &[T] {
        self.buf
    }

    pub fn buf_mut(&mut self) -> &mut [T] {
        self.buf
    }

    pub fn user(&self) -> &U {
        &self.user
    }

    pub fn is_last(&self) -> bool {
        self.last
    }
}

impl<'a, U, T> Drop for Block<'a, U, T> {
    fn drop(&mut self) {
        log!(LogFlags::LibDataChan, "{}: sending reply", self.name);
        self.is.reply_error(Code::Success).ok();
    }
}

pub struct BlockIterator<'a, U, T> {
    recv: &'a Receiver,
    seen_last: bool,
    phantom: PhantomData<(U, T)>,
}

impl<'a, U: Serialize + Deserialize<'static> + Debug, T: Clone + 'a> Iterator
    for BlockIterator<'a, U, T>
{
    type Item = Block<'a, U, T> where T: Clone + 'a;

    fn next(&mut self) -> Option<Self::Item> {
        if self.seen_last {
            return None;
        }

        let blk = self.recv.receive().ok()?;
        self.seen_last = blk.is_last();
        Some(blk)
    }
}

pub fn create(
    recv: &Activity,
    msg_size: usize,
    slots: u32,
    buf_addr: VirtAddr,
    buf_size: GlobOff,
) -> Result<(SenderCap, ReceiverCap), Error> {
    let total_buf_size = buf_size * slots as GlobOff;
    let buf = Buffer::new(recv, buf_addr, total_buf_size)?;
    let chan_recv = ReceiverCap::new(msg_size, slots, buf)?;
    let chan_send = SenderCap::new(&chan_recv, buf_size, buf_size, msg_size, slots)?;
    Ok((chan_send, chan_recv))
}

pub fn pass_through<'r, U, F, S, R, T>(
    send: &mut S,
    recv: &'r mut R,
    items: &[T],
    last: bool,
    user: U,
    mut func: F,
) -> Result<(), Error>
where
    U: Debug + Clone + Serialize + Deserialize<'static>,
    F: FnMut(R::Block<'r, U, T>),
    S: BlockSender,
    R: BlockReceiver,
    T: Clone + 'r,
{
    assert_eq!(
        send.block_size(),
        recv.buf_size() / send.credits() as GlobOff
    );

    let buf_size = send.block_size() / size_of::<T>() as GlobOff;
    let mut iter = recv.iter();
    let mut pos = 0;

    // first push out as many blocks as we have credits
    let mut count = 0;
    while count < send.credits() && pos < items.len() {
        let last = last && pos + buf_size as usize == items.len();
        send.send_slice(&items[pos..pos + buf_size as usize], last, user.clone())?;
        count += 1;
        pos += buf_size as usize;
    }

    // now receive a block and send out a new one
    while pos < items.len() {
        let blk = iter.next().unwrap();
        func(blk);

        let last = last && pos + buf_size as usize == items.len();
        send.send_slice(&items[pos..pos + buf_size as usize], last, user.clone())?;
        pos += buf_size as usize;
    }

    // receive remaining blocks
    for blk in iter {
        func(blk);
    }

    // receive pending responses
    send.wait_all()
}
