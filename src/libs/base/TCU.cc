/*
 * Copyright (C) 2016-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
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

#include <base/CPU.h>
#include <base/Init.h>
#include <base/KIF.h>
#include <base/TCU.h>
#include <base/TMIF.h>
#include <base/util/Math.h>

namespace m3 {

INIT_PRIO_TCU TCU TCU::inst;

uint16_t TCU::HW_MOD_IDS[] = {0x06, 0x25, 0x26, 0x00, 0x01, 0x02, 0x20, 0x21, 0x24};

size_t TCU::print(const char *str, size_t len) {
    len = Math::min(len, PRINT_REGS * sizeof(reg_t) - 1);

    // make sure the string is aligned for the 8-byte accesses below
    ALIGNED(8) char aligned_buf[len];
    const char *aligned_str = str;
    if(reinterpret_cast<uintptr_t>(aligned_str) & 7) {
        memcpy(aligned_buf, str, len);
        aligned_str = aligned_buf;
    }

    uintptr_t buffer = buffer_addr();
    const reg_t *rstr = reinterpret_cast<const reg_t *>(aligned_str);
    const reg_t *end = reinterpret_cast<const reg_t *>(aligned_str + len);
    while(rstr < end) {
        CPU::write8b(buffer, *rstr);
        buffer += sizeof(reg_t);
        rstr++;
    }

    write_reg(UnprivRegs::PRINT, len);
    // wait until the print was carried out
    while(read_reg(UnprivRegs::PRINT) != 0)
        ;
    return len;
}

Errors::Code TCU::send(epid_t ep, const MsgBuf &msg, label_t replylbl, epid_t reply_ep) {
    return send_aligned(ep, msg.bytes(), msg.size(), replylbl, reply_ep);
}

Errors::Code TCU::send_aligned(epid_t ep, const void *msg, size_t len, label_t replylbl,
                               epid_t reply_ep) {
    auto msg_addr = reinterpret_cast<uintptr_t>(msg);
    write_reg(UnprivRegs::DATA_ADDR, static_cast<reg_t>(msg_addr));
    write_reg(UnprivRegs::DATA_SIZE, static_cast<reg_t>(len));
    if(replylbl)
        write_reg(UnprivRegs::ARG1, replylbl);
    CPU::compiler_barrier();
    return perform_send_reply(msg_addr, build_command(ep, CmdOpCode::SEND, reply_ep));
}

Errors::Code TCU::reply(epid_t ep, const MsgBuf &reply, size_t msg_off) {
    return reply_aligned(ep, reply.bytes(), reply.size(), msg_off);
}

Errors::Code TCU::reply_aligned(epid_t ep, const void *reply, size_t len, size_t msg_off) {
    auto reply_addr = reinterpret_cast<uintptr_t>(reply);
    write_reg(UnprivRegs::DATA_ADDR, static_cast<reg_t>(reply_addr));
    write_reg(UnprivRegs::DATA_SIZE, static_cast<reg_t>(len));
    CPU::compiler_barrier();
    return perform_send_reply(reply_addr, build_command(ep, CmdOpCode::REPLY, msg_off));
}

Errors::Code TCU::perform_send_reply(uintptr_t addr, reg_t cmd) {
    while(true) {
        write_reg(UnprivRegs::COMMAND, cmd);

        auto res = get_error();
        if(res == Errors::TRANSLATION_FAULT) {
            TMABI::call2(Operation::TRANSL_FAULT, addr, KIF::Perm::R);
            continue;
        }
        return res;
    }
}

Errors::Code TCU::read(epid_t ep, void *data, size_t size, goff_t off) {
    auto res = perform_transfer(ep, reinterpret_cast<uintptr_t>(data), size, off, CmdOpCode::READ);
    // ensure that the CPU is not reading the read data before the TCU is finished
    CPU::memory_barrier();
    return res;
}

Errors::Code TCU::write(epid_t ep, const void *data, size_t size, goff_t off) {
    // ensure that the TCU is not reading the data before the CPU has written everything
    CPU::memory_barrier();
    return perform_transfer(ep, reinterpret_cast<uintptr_t>(data), size, off, CmdOpCode::WRITE);
}

Errors::Code TCU::perform_transfer(epid_t ep, uintptr_t data_addr, size_t size, goff_t off,
                                   CmdOpCode cmd) {
    while(size > 0) {
        size_t amount = Math::min(size, PAGE_SIZE - (data_addr & PAGE_MASK));
        write_reg(UnprivRegs::DATA_ADDR, static_cast<reg_t>(data_addr));
        write_reg(UnprivRegs::DATA_SIZE, static_cast<reg_t>(amount));
        write_reg(UnprivRegs::ARG1, off);
        CPU::compiler_barrier();
        write_reg(UnprivRegs::COMMAND, build_command(ep, cmd));

        auto res = get_error();
        if(res == Errors::TRANSLATION_FAULT) {
            auto perm = cmd == CmdOpCode::READ ? KIF::Perm::W : KIF::Perm::R;
            TMABI::call2(Operation::TRANSL_FAULT, data_addr, perm);
            continue;
        }
        if(res != Errors::SUCCESS)
            return res;

        size -= amount;
        data_addr += amount;
        off += amount;
    }
    return Errors::SUCCESS;
}

}
