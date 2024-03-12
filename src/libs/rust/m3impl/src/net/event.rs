/*
 * Copyright (C) 2021-2022 Nils Asmussen, Barkhausen Institut
 * Copyright (C) 2017, Georg Kotheimer <georg.kotheimer@mailbox.tu-dresden.de>
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

use core::fmt;

use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::cap::{CapFlags, Selector};
use crate::cell::RefCell;
use crate::com::{LazyGate, RGateArgs, RecvCap, RecvGate, SGateArgs, SendCap};
use crate::errors::{Code, Error};
use crate::kif::{CapRngDesc, CapType};
use crate::mem::{self, MaybeUninit, MsgBuf};
use crate::net::{Endpoint, IpAddr, Port};
use crate::rc::Rc;
use crate::tcu::{Header, Message};
use crate::tiles::{Activity, OwnActivity};
use crate::util::math;

const MSG_SIZE: usize = 2048;
const MSG_CREDITS: usize = 4;
const MSG_BUF_SIZE: usize = MSG_SIZE * MSG_CREDITS;

const REPLY_SIZE: usize = 32;
const REPLY_BUF_SIZE: usize = REPLY_SIZE * MSG_CREDITS;

/// The maximum transmission unit when sending network packets via TCU messages
// The receive buffer slots are 2048 bytes, but we need to substract the TCU header and the other
// fields in DataMessage.
pub const MTU: usize = MSG_SIZE - (mem::size_of::<Header>() + 4 * mem::size_of::<u64>());

/// The different network event types
#[derive(Copy, Clone, Debug, Eq, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[repr(u64)]
pub enum NetEventType {
    /// A data event for network packet (both directions)
    Data,
    /// Socket is now connected (server -> client)
    Connected,
    /// Socket was closed (server -> client)
    Closed,
    /// Socket should be closed (client -> server)
    CloseReq,
}

#[doc(hidden)]
#[repr(C, align(2048))]
pub struct DataMessage {
    ty: NetEventType,
    pub addr: u64,
    pub port: u64,
    pub size: u64,
    pub data: [u8; MTU],
}

#[doc(hidden)]
#[repr(C)]
pub struct ConnectedMessage {
    ty: NetEventType,
    pub remote_addr: u64,
    pub remote_port: u64,
}

impl ConnectedMessage {
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            ty: NetEventType::Connected,
            remote_addr: endpoint.addr.0 as u64,
            remote_port: endpoint.port as u64,
        }
    }
}

impl fmt::Debug for ConnectedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "remote={}",
            Endpoint::new(IpAddr(self.remote_addr as u32), self.remote_port as Port)
        )
    }
}

#[doc(hidden)]
#[repr(C)]
pub struct ClosedMessage {
    ty: NetEventType,
}

impl Default for ClosedMessage {
    fn default() -> Self {
        Self {
            ty: NetEventType::Closed,
        }
    }
}

impl fmt::Debug for ClosedMessage {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

#[doc(hidden)]
#[repr(C)]
pub struct CloseReqMessage {
    ty: NetEventType,
}

impl Default for CloseReqMessage {
    fn default() -> Self {
        Self {
            ty: NetEventType::CloseReq,
        }
    }
}

impl fmt::Debug for CloseReqMessage {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(())
    }
}

#[derive(Eq, PartialEq)]
enum NetEventSide {
    Client,
    Server,
}

/// A channel for events between client and server
///
/// The `NetEventChannel` is used to exchange events and data between the client and the server. The
/// channel is bidirectional as we need to send events and data in both directions and supports
/// multiple messages in each direction without blocking.
pub struct NetEventChannel {
    side: NetEventSide,
    rgate: RecvGate,
    rpl_gate: RecvGate,
    sgate: RefCell<LazyGate<SendCap>>,
}

impl NetEventChannel {
    /// Creates a new `NetEventChannel` for the server side with objects bound to the given
    /// selectors
    pub fn new_server(caps: Selector) -> Result<Rc<Self>, Error> {
        let rgate = RecvGate::new_with(
            RGateArgs::default()
                .sel(caps + 0)
                .msg_order(math::next_log2(MSG_SIZE))
                .order(math::next_log2(MSG_BUF_SIZE)),
        )?;

        SendCap::new_with(
            SGateArgs::new(&rgate)
                .sel(caps + 3)
                .credits(MSG_CREDITS as u32)
                .flags(CapFlags::KEEP_CAP),
        )?;

        let rgate_cli = RecvCap::new_with(
            RGateArgs::default()
                .sel(caps + 2)
                .msg_order(math::next_log2(MSG_SIZE))
                .order(math::next_log2(MSG_BUF_SIZE))
                .flags(CapFlags::KEEP_CAP),
        )?;
        let sgate = SendCap::new_with(
            SGateArgs::new(&rgate_cli)
                .sel(caps + 1)
                .credits(MSG_CREDITS as u32)
                .flags(CapFlags::KEEP_CAP),
        )?;

        let rpl_gate = RecvGate::new(math::next_log2(REPLY_BUF_SIZE), math::next_log2(REPLY_SIZE))?;

        Ok(Rc::new(Self {
            side: NetEventSide::Server,
            rgate,
            rpl_gate,
            sgate: RefCell::new(LazyGate::new(sgate.sel())),
        }))
    }

    /// Creates a new `NetEventChannel` for the client side with objects bound to the given
    /// selectors
    pub fn new_client(caps: Selector) -> Result<Rc<Self>, Error> {
        let rgate = RecvGate::new_bind(caps + 0)?;
        let rpl_gate = RecvGate::new(math::next_log2(REPLY_BUF_SIZE), math::next_log2(REPLY_SIZE))?;

        Ok(Rc::new(Self {
            side: NetEventSide::Client,
            rgate,
            rpl_gate,
            sgate: RefCell::new(LazyGate::new(caps + 1)),
        }))
    }

    /// Wait until new messages have been received
    pub fn wait_for_events(&self) {
        // ignore errors
        OwnActivity::wait_for(Some(self.rgate.ep()), None, None).ok();
    }

    /// Wait until new messages can be send
    pub fn wait_for_credits(&self) {
        // ignore errors
        OwnActivity::wait_for(Some(self.rpl_gate.ep()), None, None).ok();
    }

    /// Returns true if messages can be send
    pub fn can_send(&self) -> Result<bool, Error> {
        self.sgate.borrow_mut().get()?.can_send()
    }

    /// Returns true if there are any events to read
    pub fn has_events(&self) -> bool {
        self.rgate.has_msgs()
    }

    /// Returns true if our [`SendGate`] has full credits
    ///
    /// This is the case if the server has replied to all previously send messages.
    pub fn has_all_credits(&self) -> bool {
        self.sgate.borrow_mut().get().unwrap().credits().unwrap() == MSG_CREDITS as u32
    }

    /// Fetches the next event from the queue
    pub fn fetch_event(self: &Rc<Self>) -> Option<NetEvent> {
        match self.rgate.fetch() {
            Err(e) if e.code() == Code::NotFound => None,
            Err(_) => panic!("unexpected error in fetch_event"),
            Ok(msg) => Some(NetEvent::new(msg, self.clone())),
        }
    }

    /// Sends the given event to the other side
    pub fn send_event<E>(&self, event: E) -> Result<(), Error> {
        let mut msg_buf = MsgBuf::borrow_def();
        msg_buf.set(event);
        self.sgate
            .borrow_mut()
            .get()?
            .send(&msg_buf, &self.rpl_gate)
    }

    /// Builds a data message for sending
    ///
    /// Expects the endpoint to send the message to, the size of the message and a function that
    /// populates the message data.
    pub fn build_data_message<F>(&self, endpoint: Endpoint, size: usize, populate: F) -> DataMessage
    where
        F: FnOnce(&mut [u8]),
    {
        assert!(size <= MTU);

        #[allow(invalid_value)]
        #[allow(clippy::uninit_assumed_init)]
        let mut msg = DataMessage {
            ty: NetEventType::Data,
            addr: endpoint.addr.0 as u64,
            port: endpoint.port as u64,
            size: size as u64,
            // safety: data[0..size] will be initialized below; the rest will not be sent
            data: unsafe { MaybeUninit::uninit().assume_init() },
        };

        populate(&mut msg.data[0..size]);
        msg
    }

    /// Sends the given data message to the other side
    pub fn send_data(&self, msg: &DataMessage) -> Result<(), Error> {
        // we need to make sure here that we have enough space for the replies. therefore, we need
        // to fetch&ACK all available replies before sending. but there is still a race: if we have
        // currently 0 credits (4 msgs in flight), but no replies yet for our previous sends and if
        // we receive one reply between fetch_replies() and the send, we have one credit (and
        // therefore the send succeeds), but we didn't make room for the additional reply. thus, we
        // have still 4 msgs in flight, but only room for 3 replies. we fix that by checking first
        // whether we have credits and only then fetch&send. we might still receive one reply
        // between fetch_replies() and send, but that is fine, because we send only one message at a
        // time and reserved room for its reply.
        if self.can_send()? {
            self.fetch_replies();

            let msg_size = 4 * mem::size_of::<u64>() + msg.size as usize;
            self.sgate.borrow_mut().get()?.send_aligned(
                msg as *const _ as *const u8,
                msg_size,
                &self.rpl_gate,
            )
        }
        else {
            Err(Error::new(Code::NoCredits))
        }
    }

    /// Fetch all replies that the other side sent to us
    pub fn fetch_replies(&self) {
        while let Ok(reply) = self.rpl_gate.fetch() {
            self.rpl_gate.ack_msg(reply).unwrap();
        }
    }
}

impl Drop for NetEventChannel {
    fn drop(&mut self) {
        if self.side == NetEventSide::Server {
            // revoke client caps
            Activity::own()
                .revoke(
                    CapRngDesc::new(CapType::Object, self.rgate.sel() + 2, 2),
                    false,
                )
                .unwrap();
        }
    }
}

/// A network event exchanged over the [`NetEventChannel`]
pub struct NetEvent {
    msg: &'static Message,
    channel: Rc<NetEventChannel>,
}

impl NetEvent {
    fn new(msg: &'static Message, channel: Rc<NetEventChannel>) -> Self {
        Self { msg, channel }
    }

    /// Returns the type of event
    pub fn msg_type(&self) -> NetEventType {
        NetEventType::try_from(self.msg.as_words()[0]).unwrap()
    }

    /// Returns a reference to the message, interpreted as `T`
    pub fn msg<T>(&self) -> &T {
        // TODO improve that
        unsafe {
            let slice = &*(self.msg.as_words() as *const [u64] as *const [T]);
            &slice[0]
        }
    }
}

impl Drop for NetEvent {
    fn drop(&mut self) {
        // reply empty message; ignore failures here
        let reply = MsgBuf::borrow_def();
        self.channel.rgate.reply(&reply, self.msg).ok();
    }
}
