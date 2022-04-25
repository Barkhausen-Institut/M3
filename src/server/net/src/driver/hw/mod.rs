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

use core::slice;

use m3::col::Vec;
use m3::com::MemGate;
use m3::errors::{Code, Error};
use m3::goff;
use m3::kif::{PageFlags, Perm};
use m3::tiles::Activity;
use m3::vec;

use smoltcp::time::Instant;

extern "C" {
    pub fn axieth_init(virt: goff, phys: goff, size: usize) -> isize;
    pub fn axieth_deinit();
    pub fn axieth_send(packet: *const u8, len: usize) -> i32;
    pub fn axieth_recv(buffer: *mut u8, len: usize) -> usize;
}

const RX_BUF_SIZE: usize = 2 * 1024 * 1024;
const ALL_BUF_SIZE: usize = RX_BUF_SIZE + 0x21000; // see axieth.cc
const BUF_VIRT_ADDR: goff = 0x3000_0000;
const MTU: usize = 1500;

pub struct AXIEthDevice {
    _bufs: MemGate,
    rx_buf: Option<Vec<u8>>,
    tx_buf: usize,
}

impl AXIEthDevice {
    pub fn new() -> Result<Self, Error> {
        let bufs = MemGate::new(ALL_BUF_SIZE, Perm::RW)?;
        Activity::own()
            .pager()
            .unwrap()
            .map_mem(BUF_VIRT_ADDR, &bufs, ALL_BUF_SIZE, Perm::RW)?;
        let phys = bufs.region()?.0.to_phys(PageFlags::RW)?;

        let res = unsafe { axieth_init(BUF_VIRT_ADDR, phys, RX_BUF_SIZE) };
        if res < 0 {
            Err(Error::new(Code::NotFound))
        }
        else {
            Ok(Self {
                _bufs: bufs,
                rx_buf: None,
                tx_buf: res as usize,
            })
        }
    }
}

impl Drop for AXIEthDevice {
    fn drop(&mut self) {
        unsafe {
            axieth_deinit();
        }
    }
}

impl<'a> smoltcp::phy::Device<'a> for AXIEthDevice {
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.max_transmission_unit = MTU;
        // TODO use checksum offloading
        caps.checksum.ipv4 = smoltcp::phy::Checksum::Both;
        caps.checksum.udp = smoltcp::phy::Checksum::Both;
        caps.checksum.tcp = smoltcp::phy::Checksum::Both;
        caps
    }

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        if self.rx_buf.is_none() {
            self.rx_buf = Some(vec![0u8; MTU]);
        }

        let buf = self.rx_buf.as_mut().unwrap();
        let res = unsafe { axieth_recv((&mut buf[..]).as_mut_ptr(), buf.len()) };
        if res == 0 {
            None
        }
        else {
            let mut buffer = self.rx_buf.take().unwrap();
            buffer.resize(res, 0);
            let rx = RxToken { buffer };
            let tx = TxToken {
                tx_buf: self.tx_buf,
            };
            Some((rx, tx))
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(TxToken {
            tx_buf: self.tx_buf,
        })
    }
}

pub struct RxToken {
    buffer: Vec<u8>,
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        f(&mut self.buffer[..])
    }
}

pub struct TxToken {
    tx_buf: usize,
}

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        assert!(len <= 4096);
        // safety: we know that tx_buf is properly aligned and one page large
        let buffer = unsafe { slice::from_raw_parts_mut(self.tx_buf as *mut u8, len) };
        // fill buffer with "to be send" data
        let res = f(buffer)?;

        match unsafe { axieth_send(buffer.as_ptr(), buffer.len()) } {
            0 => Ok(res),
            _ => Err(smoltcp::Error::Exhausted),
        }
    }
}
