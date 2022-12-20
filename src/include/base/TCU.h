/*
 * Copyright (C) 2015-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019-2021 Nils Asmussen, Barkhausen Institut
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

#pragma once

#include <base/CPU.h>
#include <base/Common.h>
#include <base/Env.h>
#include <base/Errors.h>
#include <base/util/Util.h>

#include <assert.h>
#include <string.h>

namespace kernel {
class TCU;
}

namespace m3 {

class Machine;
class MemGate;
class SendGate;
class RecvGate;
class TimeInstant;
class Activity;

/**
 * A tile id, consisting of a chip and chip-local tile id
 */
class TileId {
public:
    typedef uint8_t chipid_t;
    typedef uint8_t tileid_t;
    typedef uint16_t raw_t;

    /**
     * Constructs a new tile id from the given raw id (e.g., as stored in TCUs)
     *
     * @param raw the raw 16-bit value that contains both the chip id and chip-local tile id
     * @return the created TileId
     */
    static TileId from_raw(raw_t raw) noexcept {
        return TileId(raw);
    }

    /**
     * Constructs a new tile id from the given raw representation
     *
     * @param raw the raw representation
     */
    explicit TileId(raw_t raw = 0) noexcept : id(raw) {
    }

    /**
     * Constructs a new tile id out of the given chip and chip-local tile id
     *
     * @param chip the chip id
     * @param tile the chip-local tile id
     */
    explicit TileId(chipid_t chip, tileid_t tile) noexcept
        : id(static_cast<raw_t>(chip) << 8 | static_cast<raw_t>(tile)) {
    }

    /**
     * @return the chip id
     */
    chipid_t chip() const noexcept {
        return id >> 8;
    }
    /**
     * @return the chip-local tile id
     */
    tileid_t tile() const noexcept {
        return id & 0xFF;
    }
    /**
     * @return the raw representation as used in the TCU, for example
     */
    raw_t raw() const noexcept {
        return id;
    }

    void format(OStream &os, const FormatSpecs &) const {
        format_to(os, "C{}T{:02}"_cf, chip(), tile());
    }

private:
    raw_t id;
};

class MsgBuf {
public:
    static constexpr size_t MAX_MSG_SIZE = 512;

    explicit MsgBuf() noexcept : _pos() {
    }

    MsgBuf(const MsgBuf &os) noexcept : _pos(os._pos) {
        if(_pos)
            memcpy(_bytes, os._bytes, _pos);
    }
    MsgBuf &operator=(const MsgBuf &os) noexcept {
        if(&os != this) {
            _pos = os._pos;
            if(_pos)
                memcpy(_bytes, os._bytes, _pos);
        }
        return *this;
    }

    void *bytes() noexcept {
        return _bytes;
    }
    const void *bytes() const noexcept {
        return _bytes;
    }
    size_t size() const noexcept {
        return _pos;
    }

    template<typename T>
    T &cast() noexcept {
        _pos = sizeof(T);
        return *reinterpret_cast<T *>(_bytes);
    }

    template<typename T>
    const T &get() const noexcept {
        assert(_pos >= sizeof(T));
        return *reinterpret_cast<const T *>(_bytes);
    }

    void set_size(size_t size) noexcept {
        _pos = size;
    }

private:
    uint8_t _bytes[MAX_MSG_SIZE];
    size_t _pos;
} PACKED ALIGNED(512);

class TCU {
    friend class kernel::TCU;
    friend class Machine;
    friend class MemGate;
    friend class SendGate;
    friend class RecvGate;
    friend class TimeInstant;
    friend class Activity;

    explicit TCU() {
    }

public:
    typedef uint64_t reg_t;

    static const uintptr_t MMIO_ADDR = 0xF000'0000;
    static const size_t MMIO_SIZE = PAGE_SIZE * 2;
    static const uintptr_t MMIO_PRIV_ADDR = MMIO_ADDR + MMIO_SIZE;
    static const size_t MMIO_PRIV_SIZE = PAGE_SIZE;

    static const reg_t INVALID_EP = 0xFFFF;
    static const reg_t INVALID_ACT = 0xFFFF;
    static const reg_t NO_REPLIES = INVALID_EP;
    static const reg_t UNLIM_CREDITS = 0x3F;

private:
    static const size_t EXT_REGS = 2;
    static const size_t PRIV_REGS = 5;
    static const size_t UNPRIV_REGS = 5;
    static const size_t EP_REGS = 3;
    static const size_t PRINT_REGS = 32;

    enum class ExtRegs {
        FEATURES = 0,
        EXT_CMD = 1,
    };

    enum class PrivRegs {
        CORE_REQ = 0,
        PRIV_CMD = 1,
        PRIV_CMD_ARG = 2,
        CUR_ACT = 3,
        CLEAR_IRQ = 4,
    };

    enum class UnprivRegs {
        COMMAND = EXT_REGS + 0,
        DATA = EXT_REGS + 1,
        ARG1 = EXT_REGS + 2,
        CUR_TIME = EXT_REGS + 3,
        PRINT = EXT_REGS + 4,
    };

    enum StatusFlags : reg_t {
        PRIV = 1 << 0,
    };

    enum class EpType {
        INVALID,
        SEND,
        RECEIVE,
        MEMORY
    };

    enum class CmdOpCode {
        IDLE = 0,
        SEND = 1,
        REPLY = 2,
        READ = 3,
        WRITE = 4,
        FETCH_MSG = 5,
        ACK_MSG = 6,
        SLEEP = 7,
    };

    enum class PrivCmdOpCode {
        IDLE = 0,
        INV_PAGE = 1,
        INV_TLB = 2,
        INS_TLB = 3,
        XCHG_ACT = 4,
        SET_TIMER = 5,
        ABORT_CMD = 6,
        FLUSH_CACHE = 7,
    };

    enum class ExtCmdOpCode {
        IDLE = 0,
        INV_EP = 1,
        RESET = 2,
    };

public:
    enum class IRQ {
        CORE_REQ = 0,
        TIMER = 1,
    };

    enum MemFlags : reg_t {
        R = 1 << 0,
        W = 1 << 1,
    };

    struct Header {
        enum {
            FL_REPLY = 1 << 0,
        };

        uint32_t flags : 1, replySize : 4, senderTile : 14, length : 13;
        uint16_t senderEp;
        uint16_t replyEp; // for a normal message this is the reply epId
                          // for a reply this is the enpoint that receives credits

        uint32_t replylabel;
        uint32_t label;
    } PACKED;

    struct Message : Header {
        epid_t send_ep() const {
            return senderEp;
        }
        epid_t reply_ep() const {
            return replyEp;
        }

        unsigned char data[];
    } PACKED;

    static const epid_t KPEX_SEP = 4;
    static const epid_t KPEX_REP = 5;
    static const epid_t TMUP_REP = 6;
    static const epid_t TMUP_RPLEP = 7;

    static const epid_t SYSC_SEP_OFF = 0;
    static const epid_t SYSC_REP_OFF = 1;
    static const epid_t UPCALL_REP_OFF = 2;
    static const epid_t UPCALL_RPLEP_OFF = 3;
    static const epid_t DEF_REP_OFF = 4;
    static const epid_t PG_SEP_OFF = 5;
    static const epid_t PG_REP_OFF = 6;

    static const epid_t FIRST_USER_EP = 8;
    static const epid_t STD_EPS_COUNT = 7;

    static TCU &get() {
        return inst;
    }

    bool has_missing_credits(epid_t ep) const {
        reg_t r0 = read_reg(ep, 0);
        uint16_t cur = (r0 >> 19) & 0x3F;
        uint16_t max = (r0 >> 25) & 0x3F;
        return cur < max;
    }

    uint credits(epid_t ep) const {
        reg_t r0 = read_reg(ep, 0);
        uint16_t cur = (r0 >> 19) & 0x3F;
        return cur;
    }

    bool has_msgs(epid_t ep) const {
        reg_t r2 = read_reg(ep, 2);
        return (r2 >> 32) != 0;
    }

    bool is_valid(epid_t ep) const {
        reg_t r0 = read_reg(ep, 0);
        return static_cast<EpType>(r0 & 0x7) != EpType::INVALID;
    }

    size_t print(const char *str, size_t len);

    static inline uint16_t tileid_to_nocid(TileId tile) {
        if(!tile_ids_initialized)
            init_tileid_translation();
        return tile_ids[tile.chip() * MAX_TILES + tile.tile()];
    }

    static TileId nocid_to_tileid(uint16_t raw) {
        if(!tile_ids_initialized)
            init_tileid_translation();
        for(size_t i = 0; i < MAX_TILES * MAX_CHIPS; ++i) {
            if(tile_ids[i] == raw) {
                auto chip = i / MAX_TILES;
                auto tile = i % MAX_TILES;
                return TileId(chip, tile);
            }
        }
        UNREACHED;
    }

private:
    Errors::Code send(epid_t ep, const MsgBuf &msg, label_t replylbl, epid_t reply_ep);
    Errors::Code send_aligned(epid_t ep, const void *msg, size_t len, label_t replylbl,
                              epid_t reply_ep);
    Errors::Code reply(epid_t ep, const MsgBuf &reply, size_t msg_off);
    Errors::Code reply_aligned(epid_t ep, const void *reply, size_t len, size_t msg_off);
    Errors::Code read(epid_t ep, void *msg, size_t size, goff_t off);
    Errors::Code write(epid_t ep, const void *msg, size_t size, goff_t off);

    Errors::Code perform_send_reply(uintptr_t addr, reg_t cmd);
    Errors::Code perform_transfer(epid_t ep, uintptr_t data_addr, size_t size, goff_t off,
                                  CmdOpCode cmd);

    size_t fetch_msg(epid_t ep) const {
        write_reg(UnprivRegs::COMMAND, build_command(ep, CmdOpCode::FETCH_MSG));
        get_error();
        return read_reg(UnprivRegs::ARG1);
    }

    Errors::Code ack_msg(epid_t ep, size_t msg_off) {
        // ensure that we are really done with the message before acking it
        CPU::memory_barrier();
        write_reg(UnprivRegs::COMMAND, build_command(ep, CmdOpCode::ACK_MSG, msg_off));
        return get_error();
    }

    uint64_t nanotime() const {
        return read_reg(UnprivRegs::CUR_TIME);
    }

    void sleep() {
        wait_for_msg(INVALID_EP);
    }
    void wait_for_msg(epid_t ep) {
        write_reg(UnprivRegs::COMMAND, build_command(0, CmdOpCode::SLEEP, ep));
        get_error();
    }

    void drop_msgs(size_t buf_addr, epid_t ep, label_t label) {
        // we assume that the one that used the label can no longer send messages. thus, if there
        // are no messages yet, we are done.
        word_t unread = read_reg(ep, 2) >> 32;
        if(unread == 0)
            return;

        reg_t r0 = read_reg(ep, 0);
        size_t bufsize = static_cast<size_t>(1) << ((r0 >> 35) & 0x3F);
        size_t msgsize = (r0 >> 41) & 0x3F;
        for(size_t i = 0; i < bufsize; ++i) {
            if(unread & (static_cast<size_t>(1) << i)) {
                const m3::TCU::Message *msg = offset_to_msg(buf_addr, i << msgsize);
                if(msg->label == label)
                    ack_msg(ep, i << msgsize);
            }
        }
    }

    static size_t msg_to_offset(size_t base, const Message *msg) {
        return reinterpret_cast<uintptr_t>(msg) - base;
    }
    static const Message *offset_to_msg(size_t base, size_t msg_off) {
        return reinterpret_cast<const Message *>(base + msg_off);
    }

    void clear_irq(IRQ irq) {
        write_reg(PrivRegs::CLEAR_IRQ, static_cast<reg_t>(irq));
    }

    static Errors::Code get_error() {
        while(true) {
            reg_t cmd = read_reg(UnprivRegs::COMMAND);
            if(static_cast<CmdOpCode>(cmd & 0xF) == CmdOpCode::IDLE)
                return static_cast<Errors::Code>((cmd >> 20) & 0x1F);
        }
        UNREACHED;
    }

    static reg_t read_reg(ExtRegs reg) {
        return read_reg(static_cast<size_t>(reg));
    }
    static reg_t read_reg(PrivRegs reg) {
        return read_reg(((PAGE_SIZE * 2) / sizeof(reg_t)) + static_cast<size_t>(reg));
    }
    static reg_t read_reg(UnprivRegs reg) {
        return read_reg(static_cast<size_t>(reg));
    }
    static reg_t read_reg(epid_t ep, size_t idx) {
        return read_reg(EXT_REGS + UNPRIV_REGS + EP_REGS * ep + idx);
    }
    static reg_t read_reg(size_t idx) {
        return CPU::read8b(MMIO_ADDR + idx * sizeof(reg_t));
    }

    static void write_reg(ExtRegs reg, reg_t value) {
        write_reg(static_cast<size_t>(reg), value);
    }
    static void write_reg(PrivRegs reg, reg_t value) {
        write_reg(((PAGE_SIZE * 2) / sizeof(reg_t)) + static_cast<size_t>(reg), value);
    }
    static void write_reg(UnprivRegs reg, reg_t value) {
        write_reg(static_cast<size_t>(reg), value);
    }
    static void write_reg(size_t idx, reg_t value) {
        CPU::write8b(MMIO_ADDR + idx * sizeof(reg_t), value);
    }

    static uintptr_t ext_reg_addr(ExtRegs reg) {
        return MMIO_ADDR + static_cast<size_t>(reg) * sizeof(reg_t);
    }
    static uintptr_t priv_reg_addr(PrivRegs reg) {
        return MMIO_ADDR + (PAGE_SIZE * 2) + static_cast<size_t>(reg) * sizeof(reg_t);
    }
    static uintptr_t unpriv_reg_addr(UnprivRegs reg) {
        return MMIO_ADDR + static_cast<size_t>(reg) * sizeof(reg_t);
    }
    static uintptr_t ep_regs_addr(epid_t ep) {
        return MMIO_ADDR + (EXT_REGS + UNPRIV_REGS + ep * EP_REGS) * sizeof(reg_t);
    }
    static uintptr_t buffer_addr() {
        size_t regCount = EXT_REGS + UNPRIV_REGS + TOTAL_EPS * EP_REGS;
        return MMIO_ADDR + regCount * sizeof(reg_t);
    }

    static reg_t build_command(epid_t ep, CmdOpCode c, reg_t arg = 0) {
        return static_cast<reg_t>(c) | (static_cast<reg_t>(ep) << 4) | (arg << 25);
    }

    static void config_invalid(epid_t ep) {
        write_reg(ep, 0, static_cast<reg_t>(m3::TCU::EpType::INVALID));
        write_reg(ep, 1, 0);
        write_reg(ep, 2, 0);
    }

    static void config_recv(epid_t ep, goff_t buf, unsigned order, unsigned msgorder,
                            unsigned reply_eps, uint32_t occupied = 0, uint32_t unread = 0) {
        reg_t bufSize = static_cast<reg_t>(order - msgorder);
        reg_t msgSize = static_cast<reg_t>(msgorder);
        write_reg(ep, 0,
                  static_cast<reg_t>(m3::TCU::EpType::RECEIVE) |
                      (static_cast<reg_t>(INVALID_ACT) << 3) |
                      (static_cast<reg_t>(reply_eps) << 19) | (static_cast<reg_t>(bufSize) << 35) |
                      (static_cast<reg_t>(msgSize) << 41));
        write_reg(ep, 1, buf);
        write_reg(ep, 2, static_cast<reg_t>(unread) << 32 | occupied);
    }

    static void config_send(epid_t ep, label_t lbl, TileId tile, epid_t dstep, unsigned msgorder,
                            unsigned credits, bool reply = false, epid_t crd_ep = INVALID_EP) {
        write_reg(ep, 0,
                  static_cast<reg_t>(m3::TCU::EpType::SEND) |
                      (static_cast<reg_t>(INVALID_ACT) << 3) | (static_cast<reg_t>(credits) << 19) |
                      (static_cast<reg_t>(credits) << 25) | (static_cast<reg_t>(msgorder) << 31) |
                      (static_cast<reg_t>(crd_ep) << 37) | (static_cast<reg_t>(reply) << 53));
        write_reg(ep, 1,
                  static_cast<reg_t>(dstep) | (static_cast<reg_t>(tileid_to_nocid(tile)) << 16));
        write_reg(ep, 2, lbl);
    }

    static void config_mem(epid_t ep, TileId tile, goff_t addr, size_t size, int perm) {
        write_reg(ep, 0,
                  static_cast<reg_t>(m3::TCU::EpType::MEMORY) |
                      (static_cast<reg_t>(INVALID_ACT) << 3) | (static_cast<reg_t>(perm) << 19) |
                      (static_cast<reg_t>(tileid_to_nocid(tile)) << 23));
        write_reg(ep, 1, addr);
        write_reg(ep, 2, size);
    }

    static void write_reg(epid_t ep, size_t idx, reg_t value) {
        size_t off = m3::TCU::EXT_REGS + m3::TCU::UNPRIV_REGS + m3::TCU::EP_REGS * ep + idx;
        m3::TCU::write_reg(off, value);
    }

    static void init_tileid_translation();

    static bool tile_ids_initialized;
    static uint16_t tile_ids[MAX_CHIPS * MAX_TILES];

    static TCU inst;
};

}
