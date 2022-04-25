/*
 * Copyright (C) 2021, Tendsin Mende <tendsin.mende@mailbox.tu-dresden.de>
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

#![no_std]

use m3::col::{String, ToString, Vec};
use m3::env;
use m3::errors::{Code, Error, VerboseError};
use m3::format;
use m3::mem;
use m3::net::{self, IpAddr, RawSocket, RawSocketArgs, DNS};
use m3::println;
use m3::session::NetworkManager;
use m3::time::{TimeDuration, TimeInstant};
use m3::util;
use m3::vec;
use m3::vfs::{FileEvent, FileRef, FileWaiter};

#[repr(packed, C)]
struct IPv4Header {
    version_size: u8,
    type_of_service: u8,
    packet_size: u16,
    packet_id: u16,
    frag_offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src: u32,
    dst: u32,
}

const DONT_FRAGMENT: u16 = 0x4000;

#[repr(packed, C)]
struct ICMP {
    // header
    ty: u8,
    code: u8,
    checksum: u16,

    // data (for echo and echo reply)
    identifier: u16,
    sequence: u16,
}

const IP_PROTO_ICMP: u8 = 0x01;
const ICMP_CMD_ECHO: u8 = 0x08;
const ICMP_CMD_ECHO_REPLY: u8 = 0x00;

fn send_echo(
    buf: &mut [u8],
    sock: &FileRef<RawSocket>,
    src: IpAddr,
    dest: IpAddr,
    nbytes: usize,
    seq: u16,
    ttl: u8,
) -> Result<(), Error> {
    let total: u16 = (mem::size_of::<IPv4Header>() + mem::size_of::<ICMP>() + nbytes) as u16;

    // build IP header
    let mut ip = IPv4Header {
        version_size: (4 << 4) | 5,
        type_of_service: 0,
        packet_size: total.to_be(),
        packet_id: 0,
        frag_offset: DONT_FRAGMENT.to_be(),
        ttl,
        protocol: IP_PROTO_ICMP,
        checksum: 0,
        src: src.0.to_be(),
        dst: dest.0.to_be(),
    };
    ip.checksum = (!net::data_checksum(util::object_to_bytes(&ip))).to_be();
    // copy to buffer
    buf[0..mem::size_of::<IPv4Header>()].copy_from_slice(util::object_to_bytes(&ip));
    let icmp_buf = &mut buf[mem::size_of::<IPv4Header>()..];

    // build ICMP header
    let mut icmp = ICMP {
        code: 0,
        ty: ICMP_CMD_ECHO,
        checksum: 0,
        identifier: seq.to_be(),
        sequence: seq.to_be(),
    };
    // copy header to buffer
    icmp_buf[0..mem::size_of::<ICMP>()].copy_from_slice(util::object_to_bytes(&icmp));
    // append payload
    let payload_buf = &mut icmp_buf[mem::size_of::<ICMP>()..];
    for i in payload_buf.iter_mut().take(nbytes) {
        *i = 0;
    }
    // generate checksum for header and payload
    icmp.checksum = (!net::data_checksum(&icmp_buf[..mem::size_of::<ICMP>() + nbytes])).to_be();
    // copy to buffer again
    icmp_buf[0..mem::size_of::<ICMP>()].copy_from_slice(util::object_to_bytes(&icmp));

    sock.borrow_as().send(&buf[0..total as usize])
}

fn recv_reply(
    buf: &mut [u8],
    sock: &mut FileRef<RawSocket>,
    timeout: TimeDuration,
) -> Result<(), VerboseError> {
    let send_time = TimeInstant::now();

    loop {
        // wait for a response
        if !timeout.is_zero() {
            let mut waiter = FileWaiter::default();
            waiter.add(sock.fd(), FileEvent::INPUT);
            waiter.wait_for(timeout);

            if !sock.borrow_as().has_data() {
                return Err(VerboseError::new(
                    Code::Timeout,
                    "ICMP reply timed out".to_string(),
                ));
            }
        }

        sock.borrow_as().recv(buf)?;
        let recv_time = TimeInstant::now();

        let icmp = unsafe {
            &*buf
                .as_mut_ptr()
                .add(mem::size_of::<IPv4Header>())
                .cast::<ICMP>()
        };
        if icmp.ty != ICMP_CMD_ECHO_REPLY {
            // ignore these packets; with the loopback device we receive both our request and the
            // response.
            continue;
        }

        let ip = unsafe { &*buf.as_mut_ptr().cast::<IPv4Header>() };
        let total = u16::from_be(ip.packet_size);
        let ttl = ip.ttl;
        let src = IpAddr::new_from_raw(u32::from_be(ip.src));

        println!(
            "{} bytes from {}: icmp_seq={}, ttl={}, time={} us",
            total,
            src,
            u16::from_be(icmp.sequence),
            ttl,
            recv_time.duration_since(send_time).as_micros()
        );
        break;
    }

    Ok(())
}

#[derive(Clone, Debug)]
pub struct PingSettings {
    ttl: u8,
    nbytes: usize,
    count: u16,
    interval: TimeDuration,
    timeout: TimeDuration,
    dest: String,
}

impl core::default::Default for PingSettings {
    fn default() -> Self {
        PingSettings {
            ttl: 64,
            nbytes: 56,
            count: 5,
            interval: TimeDuration::from_secs(1),
            timeout: TimeDuration::ZERO,
            dest: String::new(),
        }
    }
}

fn usage() -> ! {
    println!("Usage: {} [options] <address>", env::args().next().unwrap());
    println!();
    println!("    -c <count>    : perform <count> pings (default: 10)");
    println!("    -s <n>        : use <n> bytes of payload (default: 56)");
    println!("    -t <ttl>      : use <ttl> as time-to-live (default: 64)");
    println!("    -i <interval> : sleep <interval> ms between pings (default: 1000)");
    println!("    -W <timeout>  : wait <timeout> ms for each reply (default: 0 = infinite)");
    m3::exit(1);
}

fn parse_arg<T: core::str::FromStr>(arg: &str, name: &str) -> Result<T, VerboseError> {
    arg.parse::<T>().map_err(|_| {
        VerboseError::new(Code::InvArgs, format!("Could not parse {} '{}'", name, arg))
    })
}

fn parse_args() -> Result<PingSettings, VerboseError> {
    let mut settings = PingSettings::default();

    let args: Vec<&str> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i] {
            "-c" => {
                settings.count = parse_arg(args[i + 1], "count")?;
            },
            "-s" => {
                settings.nbytes = parse_arg(args[i + 1], "payload size")?;
            },
            "-t" => {
                settings.ttl = parse_arg(args[i + 1], "time-to-live")?;
            },
            "-i" => {
                settings.interval = TimeDuration::from_millis(parse_arg(args[i + 1], "interval")?);
            },
            "-W" => {
                settings.timeout = TimeDuration::from_millis(parse_arg(args[i + 1], "timeout")?);
            },
            _ => break,
        }
        // move forward 2 by default, since most arguments have a value
        i += 2;
    }

    if i >= args.len() {
        return Err(VerboseError::new(
            Code::InvArgs,
            "Missing arguments".to_string(),
        ));
    }

    settings.dest = args[i].to_string();

    if settings.nbytes > 1024 {
        return Err(VerboseError::new(
            Code::InvArgs,
            "Max. payload size is 1024 bytes".to_string(),
        ));
    }

    Ok(settings)
}

#[no_mangle]
pub fn main() -> i32 {
    // parse arguments
    let settings = parse_args().unwrap_or_else(|e| {
        println!("Invalid arguments: {}", e);
        usage();
    });

    let nm = NetworkManager::new("net").expect("connecting to net failed");

    let mut raw_socket = RawSocket::new(
        RawSocketArgs::new(nm.clone())
            .send_buffer(8, 64 * 1024)
            .recv_buffer(8, 64 * 1024),
        Some(IP_PROTO_ICMP),
    )
    .expect("creating raw socket failed");

    let src_ip = nm.ip_addr().expect("Unable to get own IP address");

    let mut dns = DNS::default();
    let dest_ip = dns
        .get_addr(nm, &settings.dest, TimeDuration::from_secs(3))
        .expect(&format!("Unable to resolve name '{}'", settings.dest));

    let total = mem::size_of::<IPv4Header>() + mem::size_of::<ICMP>() + settings.nbytes;
    let mut buf = vec![0u8; total];

    let mut sent = 0;
    let mut received = 0;

    println!(
        "PING {} ({}) {} data bytes",
        settings.dest, dest_ip, settings.nbytes
    );

    let mut waiter = FileWaiter::default();
    waiter.add(raw_socket.fd(), FileEvent::INPUT | FileEvent::OUTPUT);

    let start = TimeInstant::now();
    for i in 1..=settings.count {
        send_echo(
            &mut buf,
            &raw_socket,
            src_ip,
            dest_ip,
            settings.nbytes,
            i,
            settings.ttl,
        )
        .expect("Sending ICMP echo failed");
        sent += 1;

        recv_reply(&mut buf, &mut raw_socket, settings.timeout)
            .expect("Receiving ICMP echo failed");
        received += 1;

        waiter.sleep_for(settings.interval);
    }

    let end = TimeInstant::now();

    println!(
        "{} packets transmitted, {} received in {} us",
        sent,
        received,
        end.duration_since(start).as_micros()
    );

    0
}
