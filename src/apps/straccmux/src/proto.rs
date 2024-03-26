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

use base::errors::{Code, Error};
use base::io::LogFlags;
use base::log;
use base::mem::{GlobOff, MsgBuf, VirtAddr};
use base::serialize::{Deserialize, Serialize};
use base::tcu;
use base::tcu::EpId;

const EP_IN_SEND: EpId = 16;
const EP_IN_MEM: EpId = 17;
const EP_OUT_SEND: EpId = 18;
const EP_OUT_MEM: EpId = 19;
const EP_RECV: EpId = 20;

const BUF_ADDR: VirtAddr = VirtAddr::new(0x13000);
const BUF_SIZE: usize = 0x13C00 - BUF_ADDR.as_local();
const FILE_RBUF_ADDR: VirtAddr = VirtAddr::new(0x14C00);

#[allow(unused)]
#[derive(Copy, Clone, Debug, Serialize)]
#[serde(crate = "base::serde")]
#[repr(u64)]
enum Ops {
    FStat,
    Seek,
    NextIn,
    NextOut,
    Commit,
}

#[derive(Clone, Debug, Serialize)]
#[serde(crate = "base::serde")]
struct NextInOutReq {
    opcode: Ops,
    fileid: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(crate = "base::serde")]
struct NextInOutReply {
    _res: Code,
    offset: usize,
    len: usize,
}

#[derive(Default, Clone, Debug)]
struct FileView {
    off: usize,
    len: usize,
}

pub struct Executor {
    ep_off: tcu::EpId,
    input: FileView,
    output: FileView,
}

impl Executor {
    pub fn new(ep_off: tcu::EpId) -> Self {
        Self {
            ep_off,
            input: FileView::default(),
            output: FileView::default(),
        }
    }

    fn send<M: Serialize>(&self, ep: tcu::EpId, msg: M) -> Result<(), Error> {
        let mut msg_buf = MsgBuf::borrow_def();
        msg_buf.set(msg);
        tcu::TCU::send(self.ep_off + ep, &msg_buf, 0, self.ep_off + EP_RECV)
    }

    fn receive<'de, R: Deserialize<'de>>(&self) -> Result<R, Error> {
        super::receive(self.ep_off + EP_RECV, FILE_RBUF_ADDR)
    }

    pub fn step(&mut self) -> bool {
        if self.input.off == self.input.len {
            self.send(EP_IN_SEND, NextInOutReq {
                opcode: Ops::NextIn,
                fileid: 0,
            })
            .unwrap();

            let reply: NextInOutReply = self.receive().unwrap();
            log!(LogFlags::Debug, "received {:?}", reply);

            if reply.len == 0 {
                return false;
            }

            self.input.off = reply.offset;
            self.input.len = reply.len;
        }

        let amount = (self.input.len - self.input.off).min(BUF_SIZE);
        log!(
            LogFlags::Debug,
            "reading {} @ {:#x}",
            amount,
            self.input.off
        );

        tcu::TCU::read(
            self.ep_off + EP_IN_MEM,
            BUF_ADDR.as_mut_ptr(),
            amount,
            self.input.off as GlobOff,
        )
        .unwrap();
        self.input.off += amount;

        // TODO: compute

        let mut rem = amount;
        while rem > 0 {
            if self.output.off == self.output.len {
                self.send(EP_OUT_SEND, NextInOutReq {
                    opcode: Ops::NextOut,
                    fileid: 0,
                })
                .unwrap();

                let reply: NextInOutReply = self.receive().unwrap();
                log!(LogFlags::Debug, "received {:?}", reply);

                self.output.off = reply.offset;
                self.output.len = reply.len;
            }

            let amount = (self.output.len - self.output.off).min(rem);
            log!(
                LogFlags::Debug,
                "writing {} @ {:#x}",
                amount,
                self.output.off
            );
            tcu::TCU::write(
                self.ep_off + EP_OUT_MEM,
                BUF_ADDR.as_ptr(),
                amount,
                self.output.off as GlobOff,
            )
            .unwrap();
            self.output.off += amount;

            rem -= amount;
        }

        true
    }
}
