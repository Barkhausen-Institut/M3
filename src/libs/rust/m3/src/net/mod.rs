/*
 * Copyright (C) 2021-2022 Nils Asmussen, Barkhausen Institut
 * Copyright (C) 2021, Tendsin Mende <tendsin.mende@mailbox.tu-dresden.de>
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

use base::errors::{Code, Error};

mod dataqueue;
pub use self::dataqueue::DataQueue;

mod event;
pub use self::event::{
    CloseReqMessage, ClosedMessage, ConnectedMessage, DataMessage, NetEvent, NetEventChannel,
    NetEventType, MTU,
};

mod socket;
pub(crate) use self::socket::Socket;
pub use self::socket::{
    DGramSocket, DgramSocketArgs, RawSocket, RawSocketArgs, SocketArgs, State, StreamSocket,
    StreamSocketArgs, TcpSocket, UdpSocket,
};

mod dns;
pub use dns::DNS;

/// A socket descriptor
pub type Sd = usize;
/// A network port
pub type Port = u16;

pub const MSG_SIZE: usize = 2048;
pub const MSG_ORDER: u32 = 11;
pub const MSG_CREDITS: usize = 4;
pub const MSG_CREDITS_ORDER: u32 = 2;
pub const MSG_BUF_SIZE: usize = MSG_SIZE * MSG_CREDITS;
pub const MSG_BUF_ORDER: u32 = MSG_ORDER + MSG_CREDITS_ORDER;

pub const REPLY_SIZE: usize = 32;
pub const REPLY_ORDER: u32 = 6;
pub const REPLY_BUF_SIZE: usize = REPLY_SIZE * MSG_CREDITS;
pub const REPLY_BUF_ORDER: u32 = REPLY_ORDER + MSG_CREDITS_ORDER;
pub const INBAND_DATA_SIZE: usize = 2048;
pub const INBAND_DATA_CREDITS: usize = 4;
pub const INBAND_DATA_BUF_SIZE: usize = INBAND_DATA_SIZE * INBAND_DATA_CREDITS;
pub const MAX_NETDATA_SIZE: usize = 1024;

/// Represents an internet protocol (IP) address
#[derive(Debug, Default, Eq, PartialEq, Clone, Copy)]
pub struct IpAddr(pub u32);

impl IpAddr {
    /// Creates an IP address from given 4 bytes
    pub fn new(v0: u8, v1: u8, v2: u8, v3: u8) -> Self {
        IpAddr(u32::from_be_bytes([v0, v1, v2, v3]))
    }

    /// Creates an IP address from given raw value
    pub fn new_from_raw(val: u32) -> Self {
        IpAddr(val)
    }

    /// Creates an unspecified IP address
    pub fn unspecified() -> Self {
        IpAddr::new(0, 0, 0, 0)
    }
}

impl core::fmt::Display for IpAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let [b0, b1, b2, b3] = self.0.to_be_bytes();
        write!(f, "{}.{}.{}.{}", b0, b1, b2, b3)
    }
}

impl core::str::FromStr for IpAddr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parse_part = |s: &mut core::str::Split<'_, char>| {
            s.next()
                .ok_or_else(|| Error::new(Code::InvArgs))?
                .parse::<u8>()
                .map_err(|_| Error::new(Code::InvArgs))
        };

        let mut parts = s.split('.');
        let p0 = parse_part(&mut parts)?;
        let p1 = parse_part(&mut parts)?;
        let p2 = parse_part(&mut parts)?;
        let p3 = parse_part(&mut parts)?;
        Ok(Self::new(p0, p1, p2, p3))
    }
}

/// Represents an TCP/UDP endpoint consisting of an IP address and a port
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct Endpoint {
    pub addr: IpAddr,
    pub port: Port,
}

impl Endpoint {
    /// Creates a new endpoint for given IP address and port
    pub fn new(addr: IpAddr, port: Port) -> Self {
        Self { addr, port }
    }

    /// Creates an unspecified endpoint
    pub fn unspecified() -> Self {
        Self {
            addr: IpAddr::unspecified(),
            port: 0,
        }
    }
}

impl core::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    /// TCP socket
    Stream    = 0,
    /// UDP Socket
    Dgram     = 1,
    /// Raw IpSocket
    Raw       = 2,
    Undefined = 3, // Something else
}

impl SocketType {
    pub fn from_usize(ty: usize) -> Self {
        match ty {
            0 => SocketType::Stream,
            1 => SocketType::Dgram,
            2 => SocketType::Raw,
            _ => SocketType::Undefined,
        }
    }
}

/// Represents a media access control address (MAC) address
#[derive(Eq, PartialEq)]
pub struct MAC([u8; 6]);

impl MAC {
    /// Returns the broadcast address
    pub fn broadcast() -> Self {
        MAC([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    }

    /// Creates a new MAC address with given bytes
    pub fn new(b0: u8, b1: u8, b2: u8, b3: u8, b4: u8, b5: u8) -> Self {
        MAC([b0, b1, b2, b3, b4, b5])
    }

    /// Returns the MAC address as a u64
    pub fn raw(&self) -> u64 {
        ((self.0[5] as u64) << 40)
            | ((self.0[4] as u64) << 32)
            | ((self.0[3] as u64) << 24)
            | ((self.0[2] as u64) << 16)
            | ((self.0[1] as u64) << 8)
            | ((self.0[0] as u64) << 0)
    }
}

impl core::fmt::Display for MAC {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// Compute an RFC 1071 compliant checksum.
// taken from smoltcp
pub fn data_checksum(mut data: &[u8]) -> u16 {
    use core::convert::TryInto;

    let mut accum = 0;

    // For each 32-byte chunk...
    const CHUNK_SIZE: usize = 32;
    while data.len() >= CHUNK_SIZE {
        let mut d = &data[..CHUNK_SIZE];
        // ... take by 2 bytes and sum them.
        while d.len() >= 2 {
            let chunk = u16::from_be_bytes(d[..2].try_into().unwrap());
            accum += chunk as u32;
            d = &d[2..];
        }

        data = &data[CHUNK_SIZE..];
    }

    // Sum the rest that does not fit the last 32-byte chunk,
    // taking by 2 bytes.
    while data.len() >= 2 {
        let chunk = u16::from_be_bytes(data[..2].try_into().unwrap());
        accum += chunk as u32;
        data = &data[2..];
    }

    // Add the last remaining odd byte, if any.
    if let Some(&value) = data.first() {
        accum += (value as u32) << 8;
    }

    let sum = (accum >> 16) + (accum & 0xffff);
    ((sum >> 16) as u16) + (sum as u16)
}
