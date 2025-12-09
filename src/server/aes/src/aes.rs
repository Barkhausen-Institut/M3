/*
 * Copyright (C) 2019-2022 Nils Asmussen, Barkhausen Institut
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

use m3::cell::{LazyStaticRefCell, StaticCell};
use m3::com::{MemCap, Perm, Semaphore};
use m3::errors::Error;
use m3::mem::GlobOff;
use m3::rc::Rc;
use m3::server::{
    server_loop, CapExchange, ClientManager, ExcType, RequestHandler, RequestSession, Server,
    ServerSession, SessId, DEF_MAX_CLIENTS, DEF_MSG_SIZE,
};
use m3::tiles::{Activity, Tile, TileArgs};
use m3::{env, kif, tcu};

use num_enum::{IntoPrimitive, TryFromPrimitive};

use serde_repr::{Deserialize_repr, Serialize_repr};

const SPM_SIZE: GlobOff = 4096;

static TILE: LazyStaticRefCell<Rc<Tile>> = LazyStaticRefCell::default();
static MAX_CLIENTS: StaticCell<usize> = StaticCell::new(0);
static CLIENTS: StaticCell<usize> = StaticCell::new(0);
static SEM: LazyStaticRefCell<Semaphore> = LazyStaticRefCell::default();

#[derive(Copy, Clone, Debug, IntoPrimitive, TryFromPrimitive, Serialize_repr, Deserialize_repr)]
#[repr(usize)]
enum AES {
    GetMem,
}

#[derive(Debug)]
pub struct AESSession {
    _serv: ServerSession,
}

impl RequestSession for AESSession {
    fn new(serv: ServerSession, _arg: &str) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(AESSession { _serv: serv })
    }
}

impl AESSession {
    fn get_mem(
        _cli: &mut ClientManager<Self>,
        _crt: usize,
        _sid: SessId,
        xchg: &mut CapExchange<'_>,
    ) -> Result<(), Error> {
        CLIENTS.set(CLIENTS.get() + 1);
        if CLIENTS.get() == MAX_CLIENTS.get() {
            for _ in 0..CLIENTS.get() {
                SEM.borrow().up().unwrap();
            }
        }

        xchg.out_caps(kif::CapRngDesc::new_single(
            kif::CapType::Object,
            TILE.borrow().sel(),
        ));

        Ok(())
    }
}

#[no_mangle]
pub fn main() -> Result<(), Error> {
    let clients: usize = env::args().nth(1).unwrap().parse().unwrap();
    let regs: usize = env::args().nth(2).unwrap().parse().unwrap();
    let tee = env::args().nth(3).unwrap() == "1";

    MAX_CLIENTS.set(clients);
    SEM.set(Semaphore::attach("start").unwrap());

    let dummy_mcap = MemCap::new_shmem("dummy").expect("get shmem");
    let dummy_mtile = Tile::new_from_shmem("dummy").expect("get memory tile");

    let aes_tile = Tile::get_with("riscv32+coreacc", TileArgs::default().inherit_pmp(false))
        .expect("allocate AES tile");

    let aes_all = aes_tile.memory().expect("memory of AES tile");
    let aes_cap = aes_all
        .derive_cap(
            aes_tile.desc().mem_size() as GlobOff - SPM_SIZE,
            SPM_SIZE,
            Perm::RW,
        )
        .expect("derive AES mem");

    if tee && tcu::EXREG_REGS > 0 {
        // allocate all but the ones need for the mem benchs
        for _ in 0..(tcu::EXREG_REGS - clients).min(regs) {
            if let Err(e) = aes_cap.make_exclusive(&aes_tile, Activity::own().tile(), false) {
                m3::println!("Unable to add SPM exreg: {}", e);
                break;
            }
        }

        // same for DRAM (4 are used by the kernel for EP regions)
        for _ in 0..(tcu::EXREG_REGS - 4 - clients).min(regs) {
            if let Err(e) = dummy_mcap.make_exclusive(&dummy_mtile, Activity::own().tile(), false) {
                m3::println!("Unable to add DRAM exreg: {}", e);
                break;
            }
        }
    }

    TILE.set(aes_tile);

    let mut hdl = RequestHandler::new_with(DEF_MAX_CLIENTS, DEF_MSG_SIZE, 1)
        .expect("Unable to create request handler");
    let srv = Server::new("aes", &mut hdl).expect("Unable to create service 'aes'");

    hdl.reg_cap_handler(AES::GetMem, ExcType::Obt(1), AESSession::get_mem);

    server_loop(|| {
        srv.fetch_and_handle(&mut hdl)?;

        hdl.fetch_and_handle_msg();

        Ok(())
    })
    .ok();

    Ok(())
}
