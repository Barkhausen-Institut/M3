/*
 * Copyright (C) 2020-2022 Nils Asmussen, Barkhausen Institut
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

use base::cell::{StaticCell, StaticRefCell};
use base::cfg;
use base::env;
use base::errors::{Code, Error};
use base::io::LogFlags;
use base::kif;
use base::log;
use base::mem::{self, GlobAddr, GlobOff, PhysAddr, PhysAddrRaw, VirtAddr};
use base::rc::Rc;
use base::tcu::{
    ActId, EpId, ExtCmdOpCode, ExtReg, Header, Label, Message, Reg, TileId, AVAIL_EPS, EP_REGS,
    MEM_BW_BUDGET, MEM_BW_UNLIMITED, MMIO_ADDR, PMEM_PROT_EPS, TCU, UNLIM_CREDITS,
};

use crate::cap::BWQuota;
use crate::platform;
use crate::runtime::paging;
use crate::tiles::KERNEL_ID;

pub const KSYS_EP: EpId = PMEM_PROT_EPS as EpId + 0;
pub const KSRV_EP: EpId = PMEM_PROT_EPS as EpId + 1;
pub const KTMP_EP: EpId = PMEM_PROT_EPS as EpId + 2;
pub const KPEX_EP: EpId = PMEM_PROT_EPS as EpId + 3;

static BUF: StaticRefCell<[u8; 8192]> = StaticRefCell::new([0u8; 8192]);
static RBUFS: StaticRefCell<[VirtAddr; 8]> = StaticRefCell::new([VirtAddr::null(); 8]);

fn log_flag(tile: TileId) -> LogFlags {
    match tile == TileId::new_from_raw(env::boot().tile_id as u16) {
        true => LogFlags::KernKEPs,
        false => LogFlags::KernEPs,
    }
}

pub fn config_local_ep<CFG>(ep: EpId, cfg: CFG)
where
    CFG: FnOnce(&mut [Reg], (TileId, EpId)),
{
    let mut regs = [0; EP_REGS];
    cfg(
        &mut regs,
        (TileId::new_from_raw(env::boot().tile_id as u16), ep),
    );
    TCU::set_ep_regs(ep, &regs);
}

pub fn config_remote_ep<CFG>(tile: TileId, ep: EpId, cfg: CFG) -> Result<(), Error>
where
    CFG: FnOnce(&mut [Reg], (TileId, EpId)),
{
    let mut regs = [0; EP_REGS];
    cfg(&mut regs, (tile, ep));
    write_ep_remote(tile, ep, &regs)
}

pub fn config_recv(
    regs: &mut [Reg],
    tgtep: (TileId, EpId),
    act: ActId,
    buf: PhysAddr,
    buf_ord: u32,
    msg_ord: u32,
    reply_eps: Option<EpId>,
) {
    log!(
        log_flag(tgtep.0),
        "{}:EP{} = Recv[act={}, buf={}, buf_ord={}, msg_ord={}, reply_eps={:?}]",
        tgtep.0,
        tgtep.1,
        act,
        buf,
        buf_ord,
        msg_ord,
        reply_eps
    );

    TCU::config_recv(regs, act, buf, buf_ord, msg_ord, reply_eps);
}

#[allow(clippy::too_many_arguments)]
pub fn config_send(
    regs: &mut [Reg],
    tgtep: (TileId, EpId),
    act: ActId,
    lbl: Label,
    tile: TileId,
    ep: EpId,
    msg_ord: u32,
    credits: u32,
) {
    log!(
        log_flag(tgtep.0),
        "{}:EP{} = Send[act={}, lbl={:#x}, tile={}, ep={}, msg_ord={}, credits={}]",
        tgtep.0,
        tgtep.1,
        act,
        lbl,
        tile,
        ep,
        msg_ord,
        credits
    );

    TCU::config_send(regs, act, lbl, tile, ep, msg_ord, credits);
}

pub fn config_mem(
    regs: &mut [Reg],
    tgtep: (TileId, EpId),
    act: ActId,
    tile: TileId,
    addr: GlobOff,
    size: usize,
    perm: kif::Perm,
) {
    log!(
        log_flag(tgtep.0),
        "{}:{}EP{} = Mem[act={}, tile={}, addr={:#x}, size={:#x}, perm={:?}]",
        tgtep.0,
        if tgtep.1 < PMEM_PROT_EPS as EpId {
            "PMP"
        }
        else {
            ""
        },
        tgtep.1,
        act,
        tile,
        addr,
        size,
        perm
    );

    TCU::config_mem(regs, act, tile, addr, size, perm);
}

fn rbuf_addrs(virt: VirtAddr) -> (VirtAddr, PhysAddr) {
    if platform::tile_desc(platform::kernel_tile()).has_virtmem() {
        let (phys, _perm) = paging::translate(virt, kif::PageFlags::R);
        (
            virt,
            phys | (virt.as_phys() & PhysAddr::new_raw(cfg::PAGE_MASK as PhysAddrRaw)),
        )
    }
    else {
        (virt, virt.as_phys())
    }
}

pub fn recv_msgs(ep: EpId, buf: VirtAddr, ord: u32, msg_ord: u32) -> Result<(), Error> {
    static REPS: StaticCell<EpId> = StaticCell::new(8);

    if REPS.get() + (1 << (ord - msg_ord)) > AVAIL_EPS {
        return Err(Error::new(Code::NoSpace));
    }

    let (buf, phys) = rbuf_addrs(buf);
    config_local_ep(ep, |regs, tgtep| {
        config_recv(regs, tgtep, KERNEL_ID, phys, ord, msg_ord, Some(REPS.get()));
        REPS.set(REPS.get() + (1 << (ord - msg_ord)));
    });
    RBUFS.borrow_mut()[ep as usize] = buf;
    Ok(())
}

pub fn drop_msgs(rep: EpId, label: Label) {
    TCU::drop_msgs_with(RBUFS.borrow()[rep as usize], rep, label);
}

pub fn fetch_msg(rep: EpId) -> Option<&'static Message> {
    TCU::fetch_msg(rep).map(|off| TCU::offset_to_msg(RBUFS.borrow()[rep as usize], off))
}

pub fn ack_msg(rep: EpId, msg: &Message) {
    let off = TCU::msg_to_offset(RBUFS.borrow()[rep as usize], msg);
    TCU::ack_msg(rep, off).unwrap();
}

pub fn send_to(
    tile: TileId,
    ep: EpId,
    lbl: Label,
    msg: &mem::MsgBuf,
    rpl_lbl: Label,
    rpl_ep: EpId,
) -> Result<(), Error> {
    config_local_ep(KTMP_EP, |regs, tgtep| {
        // don't calculate the msg order here, because it can take some time and it doesn't really
        // matter what we set here assuming that it's large enough.
        assert!(msg.size() + mem::size_of::<Header>() <= 1 << 8);
        config_send(regs, tgtep, KERNEL_ID, lbl, tile, ep, 8, UNLIM_CREDITS);
    });
    log!(
        LogFlags::KernTCU,
        "sending {}-bytes from {:#x} to {}:{}",
        msg.size(),
        msg.bytes().as_ptr() as usize,
        tile,
        ep
    );
    TCU::send(KTMP_EP, msg, rpl_lbl, rpl_ep)
}

pub fn reply(ep: EpId, reply: &mem::MsgBuf, msg: &Message) -> Result<(), Error> {
    let msg_off = TCU::msg_to_offset(RBUFS.borrow()[ep as usize], msg);
    TCU::reply(ep, reply, msg_off)
}

pub fn read_obj<T: Default>(tile: TileId, addr: GlobOff) -> T {
    try_read_obj(tile, addr).unwrap()
}

pub fn try_read_obj<T: Default>(tile: TileId, addr: GlobOff) -> Result<T, Error> {
    let mut obj: T = T::default();
    let obj_addr = &mut obj as *mut T as *mut u8;
    try_read_mem(tile, addr, obj_addr, mem::size_of::<T>())?;
    Ok(obj)
}

pub fn read_slice<T>(tile: TileId, addr: GlobOff, data: &mut [T]) {
    try_read_slice(tile, addr, data).unwrap();
}

pub fn try_read_slice<T>(tile: TileId, addr: GlobOff, data: &mut [T]) -> Result<(), Error> {
    try_read_mem(
        tile,
        addr,
        data.as_mut_ptr() as *mut _ as *mut u8,
        data.len() * mem::size_of::<T>(),
    )
}

pub fn try_read_mem(
    src_tile: TileId,
    addr: GlobOff,
    data: *mut u8,
    size: usize,
) -> Result<(), Error> {
    config_local_ep(KTMP_EP, |regs, tgtep| {
        config_mem(regs, tgtep, KERNEL_ID, src_tile, addr, size, kif::Perm::R);
    });
    log!(
        LogFlags::KernTCU,
        "reading {} bytes from {}:{:#x}",
        size,
        src_tile,
        addr
    );
    TCU::read(KTMP_EP, data, size, 0)
}

pub fn write_slice<T>(tile: TileId, addr: GlobOff, sl: &[T]) {
    let sl_addr = sl.as_ptr() as *const u8;
    write_mem(tile, addr, sl_addr, sl.len() * mem::size_of::<T>());
}

pub fn try_write_slice<T>(tile: TileId, addr: GlobOff, sl: &[T]) -> Result<(), Error> {
    let sl_addr = sl.as_ptr() as *const u8;
    try_write_mem(tile, addr, sl_addr, sl.len() * mem::size_of::<T>())
}

pub fn write_mem(tile: TileId, addr: GlobOff, data: *const u8, size: usize) {
    try_write_mem(tile, addr, data, size).unwrap();
}

pub fn try_write_mem(
    dst_tile: TileId,
    addr: GlobOff,
    data: *const u8,
    size: usize,
) -> Result<(), Error> {
    config_local_ep(KTMP_EP, |regs, tgtep| {
        config_mem(regs, tgtep, KERNEL_ID, dst_tile, addr, size, kif::Perm::W);
    });
    log!(
        LogFlags::KernTCU,
        "writing {} bytes to {}:{:#x}",
        size,
        dst_tile,
        addr
    );
    TCU::write(KTMP_EP, data, size, 0)
}

pub fn clear(dst_tile: TileId, mut dst_addr: GlobOff, size: usize) -> Result<(), Error> {
    use base::libc;

    let mut buf = BUF.borrow_mut();
    let clear_size = core::cmp::min(size, buf.len());
    unsafe {
        libc::memset(buf.as_mut_ptr() as *mut libc::c_void, 0, clear_size);
    }

    let mut rem = size;
    while rem > 0 {
        let amount = core::cmp::min(rem, buf.len());
        try_write_slice(dst_tile, dst_addr, &buf[0..amount])?;
        dst_addr += amount as GlobOff;
        rem -= amount;
    }
    Ok(())
}

pub fn copy(
    dst_tile: TileId,
    mut dst_addr: GlobOff,
    src_tile: TileId,
    mut src_addr: GlobOff,
    size: usize,
) -> Result<(), Error> {
    let mut buf = BUF.borrow_mut();
    let mut rem = size;
    while rem > 0 {
        let amount = core::cmp::min(rem, buf.len());
        try_read_slice(src_tile, src_addr, &mut buf[0..amount])?;
        try_write_slice(dst_tile, dst_addr, &buf[0..amount])?;
        src_addr += amount as GlobOff;
        dst_addr += amount as GlobOff;
        rem -= amount;
    }
    Ok(())
}

pub fn deprivilege_tile(tile: TileId) -> Result<(), Error> {
    let reg_addr = TCU::ext_reg_addr(ExtReg::Features).as_goff();
    let mut features: u64 = try_read_obj(tile, reg_addr)?;
    features &= !1;
    try_write_slice(tile, reg_addr, &[features])
}

pub fn set_memory_bandwidth(tile: TileId, quota: &Rc<BWQuota>) -> Result<(), Error> {
    if env::boot().platform != env::Platform::Gem5 {
        // TODO unsupported
        Ok(())
    }
    else {
        // Set "unlimited" for the illegal rate of 0. we only support 0 to allow "intermediate" tile
        // caps, where all bandwidth is derived into other tile caps. The intermediate tile caps
        // cannot be used for activities, so that it doesn't matter which bandwidth is set in the
        // TCU. However, we need to keep the TCU happy by not setting the rate to 0.
        let rate = if quota.rate() == 0 {
            MEM_BW_UNLIMITED
        }
        else {
            quota.rate()
        };

        let reg: u64 =
            (rate as u64) << 32 | (MEM_BW_BUDGET as u64) << 16 | (MEM_BW_BUDGET as u64) << 0;
        try_write_slice(
            tile,
            TCU::ext_reg_addr(ExtReg::MemBandWidth).as_goff() + (quota.id() * 8),
            &[reg],
        )
    }
}

pub fn reset_tile(tile: TileId, start: bool) -> Result<(), Error> {
    let val: Reg = if start { 1 } else { 0 };
    if env::boot().platform == env::Platform::Hw {
        // TODO put the reset command into the spec so that we can use that on HW as well
        // start/stop tile
        try_write_slice(tile, MMIO_ADDR.as_goff() + 0x3028, &[val])?;
        // start/stop rocket core
        try_write_slice(tile, MMIO_ADDR.as_goff() + 0x3030, &[val])
    }
    else {
        let value = ExtCmdOpCode::Reset as Reg | (val << 9) as Reg;
        do_ext_cmd(tile, value).map(|_| ())
    }
}

pub fn glob_to_phys_remote(
    tile: TileId,
    glob: GlobAddr,
    flags: kif::PageFlags,
) -> Result<PhysAddr, Error> {
    glob.to_phys_with(flags, |ep| {
        let mut regs = [0; 3];
        if read_ep_remote(tile, ep, &mut regs).is_ok() {
            TCU::unpack_mem_regs(&regs)
        }
        else {
            None
        }
    })
}

pub fn read_ep_remote(tile: TileId, ep: EpId, regs: &mut [Reg]) -> Result<(), Error> {
    for i in 0..regs.len() {
        try_read_slice(
            tile,
            (TCU::ep_regs_addr(ep) + i * 8).as_goff(),
            &mut regs[i..i + 1],
        )?;
    }
    Ok(())
}

pub fn write_ep_remote(tile: TileId, ep: EpId, regs: &[Reg]) -> Result<(), Error> {
    for (i, r) in regs.iter().enumerate() {
        try_write_slice(tile, (TCU::ep_regs_addr(ep) + i * 8).as_goff(), &[*r])?;
    }
    Ok(())
}

pub fn invalidate_ep_remote(tile: TileId, ep: EpId, force: bool) -> Result<u32, Error> {
    log!(LogFlags::KernEPs, "{}:EP{} = invalid", tile, ep);

    let reg = ExtCmdOpCode::InvEP as Reg | ((ep as Reg) << 9) as Reg | ((force as Reg) << 25);
    do_ext_cmd(tile, reg).map(|unread| unread as u32)
}

pub fn inv_reply_remote(
    recv_tile: TileId,
    recv_ep: EpId,
    send_tile: TileId,
    send_ep: EpId,
) -> Result<(), Error> {
    log!(
        LogFlags::KernEPs,
        "{}:EP{} = invalid reply EPs at {}:EP{}",
        send_tile,
        send_ep,
        recv_tile,
        recv_ep
    );

    let mut regs = [0; EP_REGS];
    read_ep_remote(recv_tile, recv_ep, &mut regs)?;

    // if there is no occupied slot, there can't be any reply EP we have to invalidate
    let occupied = regs[2] & 0xFFFF_FFFF;
    if occupied == 0 {
        return Ok(());
    }

    let buf_size = 1 << ((regs[0] >> 35) & 0x3F);
    let reply_eps = ((regs[0] >> 19) & 0xFFFF) as EpId;
    for i in 0..buf_size {
        if (occupied & (1 << i)) != 0 {
            // load the reply EP
            read_ep_remote(recv_tile, reply_eps + i, &mut regs)?;

            // is that replying to the sender?
            let tgt_tile = ((regs[1] >> 16) & 0xFFFF) as u16;
            let crd_ep = ((regs[0] >> 37) & 0xFFFF) as EpId;
            if crd_ep == send_ep && tgt_tile == send_tile.raw() {
                invalidate_ep_remote(recv_tile, reply_eps + i, true)?;
            }
        }
    }

    Ok(())
}

fn do_ext_cmd(tile: TileId, cmd: Reg) -> Result<Reg, Error> {
    let addr = TCU::ext_reg_addr(ExtReg::ExtCmd).as_goff();
    try_write_slice(tile, addr, &[cmd])?;

    let res = loop {
        let res: Reg = try_read_obj(tile, addr)?;
        if (res & 0xF) == ExtCmdOpCode::Idle.into() {
            break res;
        }
    };

    match Code::from(((res >> 4) & 0x1F) as u32) {
        Code::Success => Ok(res >> 9),
        e => Err(Error::new(e)),
    }
}
