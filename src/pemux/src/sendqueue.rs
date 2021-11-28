/*
 * Copyright (C) 2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
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

use base::cell::StaticRefCell;
use base::errors::Error;
use base::log;
use base::mem::MsgBuf;
use base::msgqueue::{MsgQueue, MsgSender};
use base::tcu;

struct TCUSender;

impl MsgSender<()> for TCUSender {
    fn can_send(&self) -> bool {
        tcu::TCU::credits(tcu::KPEX_SEP).unwrap() > 0
    }

    fn send(&mut self, _: (), msg: &MsgBuf) -> Result<(), Error> {
        log!(crate::LOG_SQUEUE, "squeue: sending msg",);
        tcu::TCU::send(tcu::KPEX_SEP, msg, 0, tcu::KPEX_REP)
    }
}

static SQUEUE: StaticRefCell<MsgQueue<TCUSender, ()>> =
    StaticRefCell::new(MsgQueue::new(TCUSender {}));

pub fn check_replies() {
    if let Some(msg_off) = tcu::TCU::fetch_msg(tcu::KPEX_REP) {
        log!(crate::LOG_SQUEUE, "squeue: received reply",);

        // now that we've copied the message, we can mark it read
        tcu::TCU::ack_msg(tcu::KPEX_REP, msg_off).unwrap();

        SQUEUE.borrow_mut().send_pending();
    }
}

pub fn send(msg: &MsgBuf) -> Result<(), Error> {
    if !SQUEUE.borrow_mut().send((), msg)? {
        log!(crate::LOG_SQUEUE, "squeue: queuing msg",);
    }
    Ok(())
}
