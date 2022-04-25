/*
 * Copyright (C) 2022 Nils Asmussen, Barkhausen Institut
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

use core::mem;
use core::str::FromStr;

use base::col::ToString;
use base::errors::{Code, Error, VerboseError};
use base::random::LCG;
use base::rc::Rc;
use base::time::TimeDuration;
use base::vec;

use crate::net::{DGramSocket, DgramSocketArgs, Endpoint, IpAddr, Port, UdpSocket};
use crate::session::NetworkManager;
use crate::vfs::{File, FileEvent, FileWaiter};

// based on http://tools.ietf.org/html/rfc1035

const DNS_RECURSION_DESIRED: u16 = 0x100;
const DNS_PORT: Port = 53;

const TYPE_A: u16 = 1; // a host address
const CLASS_IN: u16 = 1; // the internet

#[repr(C, packed)]
struct DNSHeader {
    id: u16,
    flags: u16,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,
}

#[repr(C, packed)]
struct DNSQuestionEnd {
    ty: u16,
    cls: u16,
}

#[repr(C, packed)]
struct DNSAnswer {
    name: u16,
    ty: u16,
    cls: u16,
    ttl: u32,
    length: u16,
    // this is the data part of the answer, where we currently only support IPv4 addresses
    ip_addr: u32,
}

#[derive(Default)]
pub struct DNS {
    nameserver: IpAddr,
    random: LCG,
}

impl DNS {
    /// Translates the given name into an IP address. If the name is already an IP address, it will
    /// simply be converted into an [`IpAddr`] object. Otherwise, the name will be solved via DNS.
    ///
    /// The timeout specifies the maximum time to wait for the DNS response.
    pub fn get_addr(
        &mut self,
        netmng: Rc<NetworkManager>,
        name: &str,
        timeout: TimeDuration,
    ) -> Result<IpAddr, VerboseError> {
        if let Ok(addr) = IpAddr::from_str(name) {
            return Ok(addr);
        }

        self.resolve(netmng, name, timeout)
    }

    /// Resolves the given hostname to an IP address. Note that this method assumes that the name is
    /// not an IP address, but an actual hostname and will therefore always use DNS to resolve the
    /// name. Use [`get_addr`](Self::get_addr) if you don't know whether it's a hostname or an IP
    /// address.
    ///
    /// The timeout specifies the maximum time to wait for the DNS response.
    pub fn resolve(
        &mut self,
        netmng: Rc<NetworkManager>,
        name: &str,
        timeout: TimeDuration,
    ) -> Result<IpAddr, VerboseError> {
        if self.nameserver == IpAddr::unspecified() {
            self.nameserver = netmng.nameserver()?;
        }

        let name_len = name.len();
        let total = mem::size_of::<DNSHeader>() + name_len + 2 + mem::size_of::<DNSQuestionEnd>();
        // reserve some space for the answer as well
        let mut buffer = vec![0u8; total.max(1024)];

        let txid = self.random.get() as u16;

        // safety: we are still within the allocated vector and DNSHeader has no alignment
        // requirements
        let mut header = unsafe { &mut *(buffer.as_mut_ptr() as *mut DNSHeader) };
        // build DNS request message
        header.id = txid.to_be();
        header.flags = DNS_RECURSION_DESIRED.to_be();
        header.qd_count = 1u16.to_be();
        header.an_count = 0;
        header.ns_count = 0;
        header.ar_count = 0;

        // add hostname
        let hostname_bytes = &mut buffer[mem::size_of::<DNSHeader>()..];
        Self::convert_hostname(hostname_bytes, name)?;

        // safety: we are still within the allocated vector and DNSQuestionEnd has no alignment
        // requirements
        let mut qend = unsafe {
            &mut *(buffer
                .as_mut_ptr()
                .add(mem::size_of::<DNSHeader>() + name_len + 2)
                as *mut DNSQuestionEnd)
        };
        qend.ty = TYPE_A.to_be();
        qend.cls = CLASS_IN.to_be();

        // create socket
        let mut sock = UdpSocket::new(DgramSocketArgs::new(netmng))?;

        // send over socket
        sock.send_to(
            &mut buffer[0..total],
            Endpoint::new(self.nameserver, DNS_PORT),
        )?;

        // wait for the response
        sock.set_blocking(false)?;
        let mut waiter = FileWaiter::default();
        waiter.add(sock.fd(), FileEvent::INPUT);
        waiter.wait_for(timeout);

        // receive response
        let len = sock.recv(&mut buffer)?;
        if len < mem::size_of::<DNSHeader>() {
            return Err(VerboseError::new(
                Code::NotFound,
                "Invalid DNS response".to_string(),
            ));
        }
        if u16::from_be(header.id) != txid {
            return Err(VerboseError::new(
                Code::NotFound,
                "Received DNS response with wrong transaction id".to_string(),
            ));
        }

        let questions = u16::from_be(header.qd_count);
        let answers = u16::from_be(header.an_count);

        // skip questions
        let mut idx = mem::size_of::<DNSHeader>();
        for _ in 0..questions {
            let qlen = Self::question_length(&buffer[idx..]);
            idx += qlen + mem::size_of::<DNSQuestionEnd>();
        }

        // parse answers
        for _ in 0..answers {
            if idx + mem::size_of::<DNSAnswer>() > len {
                return Err(VerboseError::new(
                    Code::NotFound,
                    "Invalid DNS response".to_string(),
                ));
            }

            // safety: we check above whether we are in bounds and DNSAnswer has no alignment req.
            let ans = unsafe { &*(buffer.as_ptr().add(idx) as *const DNSAnswer) };
            if u16::from_be(ans.ty) == TYPE_A
                && u16::from_be(ans.length) == mem::size_of::<IpAddr>() as u16
            {
                return Ok(IpAddr::new_from_raw(u32::from_be(ans.ip_addr)));
            }
        }

        Err(VerboseError::new(
            Code::NotFound,
            "No IPv4 address in DNS response".to_string(),
        ))
    }

    fn convert_hostname(dst: &mut [u8], src: &str) -> Result<(), Error> {
        let mut idx = src.len();
        let mut part_length = 0i8;

        // we start with the \0 at the end
        dst[idx + 1] = b'\0';

        for b in src.bytes().rev() {
            if b == b'.' {
                dst[idx] = part_length as u8;
                part_length = 0;
            }
            else {
                dst[idx] = b;
                part_length = part_length
                    .checked_add(1)
                    .ok_or(Error::new(Code::InvArgs))?;
            }
            idx -= 1;
        }

        dst[idx] = part_length as u8;
        Ok(())
    }

    fn question_length(data: &[u8]) -> usize {
        let mut total = 0;
        let mut idx = 0;
        while idx < data.len() && data[idx] != 0 {
            let len = data[idx] as usize;
            // skip this name-part
            total += len + 1;
            idx += len + 1;
        }
        // skip zero ending, too
        total + 1
    }
}
