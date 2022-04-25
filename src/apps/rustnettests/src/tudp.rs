/*
 * Copyright (C) 2021 Nils Asmussen, Barkhausen Institut
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

use m3::com::Semaphore;
use m3::errors::{Code, Error};
use m3::net::{DGramSocket, DgramSocketArgs, Endpoint, State, UdpSocket, MTU};
use m3::session::NetworkManager;
use m3::test;
use m3::time::TimeDuration;
use m3::vfs::{File, FileEvent, FileRef, FileWaiter};
use m3::{wv_assert_eq, wv_assert_err, wv_assert_ok, wv_run_test};

const TIMEOUT: TimeDuration = TimeDuration::from_secs(1);

pub fn run(t: &mut dyn test::WvTester) {
    // wait once for UDP, because it's connection-less
    wv_assert_ok!(Semaphore::attach("net-udp").unwrap().down());

    wv_run_test!(t, basics);
    wv_run_test!(t, connect);
    wv_run_test!(t, data);
}

fn basics() {
    let nm = wv_assert_ok!(NetworkManager::new("net0"));

    let mut socket = wv_assert_ok!(UdpSocket::new(DgramSocketArgs::new(nm)));

    wv_assert_eq!(socket.state(), State::Closed);
    wv_assert_eq!(socket.local_endpoint(), None);

    wv_assert_ok!(socket.bind(2000));
    wv_assert_eq!(socket.state(), State::Bound);
    wv_assert_eq!(
        socket.local_endpoint(),
        Some(Endpoint::new(crate::NET0_IP.get(), 2000))
    );

    wv_assert_err!(socket.bind(2001), Code::InvState);
}

fn connect() {
    let nm = wv_assert_ok!(NetworkManager::new("net0"));

    let mut socket = wv_assert_ok!(UdpSocket::new(DgramSocketArgs::new(nm)));

    wv_assert_eq!(socket.state(), State::Closed);
    wv_assert_eq!(socket.local_endpoint(), None);

    wv_assert_ok!(socket.connect(Endpoint::new(crate::NET0_IP.get(), 2000)));
    wv_assert_eq!(socket.state(), State::Bound);
}

fn send_recv(
    waiter: &mut FileWaiter,
    socket: &mut FileRef<UdpSocket>,
    dest: Endpoint,
    send_buf: &[u8],
    recv_buf: &mut [u8],
    timeout: TimeDuration,
) -> Result<(usize, Endpoint), Error> {
    wv_assert_ok!(socket.send_to(send_buf, dest));

    waiter.wait_for(timeout);

    if socket.has_data() {
        socket.recv_from(recv_buf)
    }
    else {
        Err(Error::new(Code::Timeout))
    }
}

fn data() {
    let nm = wv_assert_ok!(NetworkManager::new("net0"));

    let mut socket = wv_assert_ok!(UdpSocket::new(DgramSocketArgs::new(nm)));

    wv_assert_ok!(socket.set_blocking(false));

    let dest = Endpoint::new(crate::DST_IP.get(), 1337);

    let mut send_buf = [0u8; 1024];
    for (i, bufi) in send_buf.iter_mut().enumerate() {
        *bufi = i as u8;
    }

    let mut recv_buf = [0u8; 1024];

    let mut waiter = FileWaiter::default();
    waiter.add(socket.fd(), FileEvent::INPUT);

    // do one initial send-receive with a higher timeout than the smoltcp-internal timeout to
    // workaround the high ARP-request delay with the loopback device.
    wv_assert_ok!(send_recv(
        &mut waiter,
        &mut socket,
        dest,
        &send_buf[0..1],
        &mut recv_buf,
        TimeDuration::from_secs(6)
    ));

    wv_assert_err!(
        socket.send_to(&m3::vec![0u8; 4096], dest),
        Code::OutOfBounds
    );
    wv_assert_err!(
        socket.send_to(&m3::vec![0u8; MTU + 1], dest),
        Code::OutOfBounds
    );

    let packet_sizes = [8, 16, 32, 64, 128, 256, 512, 1024];
    for pkt_size in &packet_sizes {
        loop {
            if let Ok((recv_size, src)) = send_recv(
                &mut waiter,
                &mut socket,
                dest,
                &send_buf[0..*pkt_size],
                &mut recv_buf,
                TIMEOUT,
            ) {
                wv_assert_eq!(*pkt_size, recv_size as usize);
                wv_assert_eq!(src, dest);
                wv_assert_eq!(&recv_buf[0..recv_size], &send_buf[0..recv_size]);
                break;
            }
        }
    }
}
