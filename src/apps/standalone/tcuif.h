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

#include <base/Common.h>
#include <base/TCU.h>

namespace kernel {

class TCU {
public:
    typedef m3::TCU::reg_t reg_t;

    static epid_t tmpEp() {
        return endpoint_num() - 1;
    }

    static size_t endpoint_num() {
        return m3::TCU::endpoints_size() / (m3::TCU::EP_REGS * sizeof(m3::TCU::reg_t));
    }

    static uint is_valid(epid_t ep) {
        return m3::TCU::get().is_valid(ep);
    }

    static uint credits(epid_t ep) {
        return m3::TCU::get().credits(ep);
    }

    static int max_credits(epid_t ep) {
        reg_t r0 = m3::TCU::read_reg(ep, 0);
#if defined(__hw22__) || defined(__hw23__)
        return (r0 >> 25) & m3::TCU::CREDIT_MASK;
#else
        return (r0 >> 26) & m3::TCU::CREDIT_MASK;
#endif
    }

    static void recv_pos(epid_t ep, uint8_t *rpos, uint8_t *wpos) {
        reg_t r0 = m3::TCU::read_reg(ep, 0);
#if defined(__hw22__) || defined(__hw23__)
        *rpos = (r0 >> 53) & 0x3F;
        *wpos = (r0 >> 47) & 0x3F;
#else
        *rpos = (r0 >> 55) & 0x7F;
        *wpos = (r0 >> 48) & 0x7F;
#endif
    }

    static void recv_masks(epid_t ep, m3::TCU::rep_bitmask_t *unread,
                           m3::TCU::rep_bitmask_t *occupied) {
#if defined(__hw22__) || defined(__hw23__)
        m3::TCU::reg_t reg = m3::TCU::read_reg(ep, 2);
        *occupied = reg & 0xFFFF'FFFF;
        *unread = reg >> 32;
#else
        *occupied = m3::TCU::read_reg(ep, 2);
        *unread = m3::TCU::read_reg(ep, 3);
#endif
    }

    static const m3::TCU::Message *fetch_msg(epid_t ep, uintptr_t base) {
        size_t off = m3::TCU::get().fetch_msg(ep);
        if(off == static_cast<size_t>(-1))
            return nullptr;
        return reinterpret_cast<const m3::TCU::Message *>(base + off);
    }

    static m3::Errors::Code ack_msg(epid_t ep, uintptr_t base, const m3::TCU::Message *msg) {
        uintptr_t msg_addr = reinterpret_cast<uintptr_t>(msg);
        reg_t off = static_cast<reg_t>(msg_addr) - base;
        return m3::TCU::get().ack_msg(ep, off);
    }

    static m3::Errors::Code send(epid_t ep, const m3::MsgBuf &msg, label_t replylbl,
                                 epid_t reply_ep) {
        return m3::TCU::get().send(ep, msg, replylbl, reply_ep);
    }

    static m3::Errors::Code send_aligned(epid_t ep, const void *msg, size_t len, label_t replylbl,
                                         epid_t reply_ep) {
        return m3::TCU::get().send_aligned(ep, msg, len, replylbl, reply_ep);
    }

    static m3::Errors::Code reply(epid_t ep, const m3::MsgBuf &reply, uintptr_t base,
                                  const m3::TCU::Message *msg) {
        uintptr_t msg_addr = reinterpret_cast<uintptr_t>(msg);
        reg_t off = static_cast<reg_t>(msg_addr) - base;
        return m3::TCU::get().reply(ep, reply, off);
    }

    static m3::Errors::Code reply_aligned(epid_t ep, const void *reply, size_t len, uintptr_t base,
                                          const m3::TCU::Message *msg) {
        uintptr_t msg_addr = reinterpret_cast<uintptr_t>(msg);
        reg_t off = static_cast<reg_t>(msg_addr) - base;
        return m3::TCU::get().reply_aligned(ep, reply, len, off);
    }

    static m3::Errors::Code read(epid_t ep, void *data, size_t size, goff_t off) {
        return m3::TCU::get().read(ep, data, size, off);
    }

    static m3::Errors::Code write(epid_t ep, const void *data, size_t size, goff_t off) {
        return m3::TCU::get().write(ep, data, size, off);
    }

    static void sleep() {
        if(m3::bootenv()->platform == m3::Platform::GEM5)
            m3::TCU::get().sleep();
    }

    static m3::Errors::Code unknown_cmd() {
        m3::TCU::reg_t unknown = static_cast<uint>(m3::TCU::CmdOpCode::SLEEP) + 1;
        m3::TCU::get().write_reg(m3::TCU::UnprivRegs::COMMAND, unknown);
        return m3::TCU::get().get_error();
    }

    static void config_invalid(epid_t ep) {
        m3::TCU::config_invalid(ep);
    }

    static void config_recv(epid_t ep, goff_t buf, unsigned order, unsigned msgorder,
                            unsigned reply_eps, m3::TCU::rep_bitmask_t occupied = 0,
                            m3::TCU::rep_bitmask_t unread = 0) {
        m3::TCU::config_recv(ep, buf, order, msgorder, reply_eps, occupied, unread);
    }

    static void config_send(epid_t ep, label_t lbl, m3::TileId tile, epid_t dstep,
                            unsigned msgorder, unsigned credits, bool reply = false,
                            epid_t crd_ep = m3::TCU::INVALID_EP) {
        m3::TCU::config_send(ep, lbl, tile, dstep, msgorder, credits, reply, crd_ep);
    }

    static void config_mem(epid_t ep, m3::TileId tile, goff_t addr, size_t size, int perm) {
        m3::TCU::config_mem(ep, tile, addr, size, perm);
    }

    static m3::Errors::Code invalidate_ep_remote(m3::TileId tile, epid_t ep, bool force,
                                                 m3::TCU::rep_bitmask_t *unread = nullptr) {
        reg_t cmd = static_cast<reg_t>(m3::TCU::ExtCmdOpCode::INV_EP) |
                    (static_cast<reg_t>(ep) << 9) | (static_cast<reg_t>(force) << 25);
        return perform_ext_cmd(tile, cmd, unread);
    }

private:
    static m3::Errors::Code perform_ext_cmd(m3::TileId tile, reg_t cmd,
                                            m3::TCU::rep_bitmask_t *unread = nullptr) {
        epid_t tmp_ep = tmpEp();
        size_t addr = m3::TCU::ext_reg_addr(m3::TCU::ExtRegs::EXT_CMD);
        config_mem(tmp_ep, tile, addr, sizeof(reg_t), m3::TCU::R | m3::TCU::W);
        m3::Errors::Code err = write(tmp_ep, &cmd, sizeof(cmd), 0);
        if(err != m3::Errors::SUCCESS)
            return err;

        reg_t res;
        do {
            err = read(tmp_ep, &res, sizeof(res), 0);
            if(err != m3::Errors::SUCCESS)
                return err;
        }
        while((res & 0xF) != 0);

        if(unread)
            *unread = res >> 9;
        return static_cast<m3::Errors::Code>((res >> 4) & 0x1F);
    }
};

}
