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

#pragma once

#include <base/Common.h>
#include <base/Errors.h>
#include <base/TCU.h>
#include <base/stream/Format.h>

#include <utility>

namespace m3 {

/**
 * The kernel interface
 */
struct KIF {
    KIF() = delete;

    /**
     * Represents an invalid selector
     */
    static const capsel_t INV_SEL = 0xFFFF;

    /**
     * Represents unlimited credits
     */
    static const uint UNLIM_CREDITS = TCU::UNLIM_CREDITS;

    /**
     * The maximum message length that can be used
     */
    static const size_t MAX_MSG_SIZE = 440;

    /**
     * The maximum string length in messages
     */
    static const size_t MAX_STR_SIZE = 64;

    static const capsel_t SEL_TILE = 0;
    static const capsel_t SEL_KMEM = 1;
    static const capsel_t SEL_ACT = 2;

    /**
     * The first selector for the endpoint capabilities
     */
    static const uint FIRST_FREE_SEL = SEL_ACT + 1;

    /**
     * The activity id of TileMux
     */
    static const uint TILEMUX_ACT_ID = 0xFFFF;

    /**
     * The permissions for MemGate
     */
    struct Perm {
        static const uint R = 1;
        static const uint W = 2;
        static const uint X = 4;
        static const uint RW = R | W;
        static const uint RWX = R | W | X;
    };

    /**
     * The flags for virtual mappings
     */
    struct PageFlags {
        static const uint R = Perm::R;
        static const uint W = Perm::W;
        static const uint X = Perm::X;
        static const uint RW = R | W;
        static const uint RX = R | X;
        static const uint RWX = R | W | X;
    };

    enum ActivityFlags {
        // whether the Tile can be shared with others
        MUXABLE = 1,
        // whether this activity gets pinned on one Tile
        PINNED = 2,
    };

    struct CapRngDesc {
        typedef xfer_t value_type;

        enum Type {
            OBJ,
            MAP,
        };

        explicit CapRngDesc() : CapRngDesc(OBJ, 0, 0) {
        }
        explicit CapRngDesc(const value_type raw[2]) : _start(raw[0]), _count(raw[1]) {
        }
        explicit CapRngDesc(Type type, capsel_t start, capsel_t count = 1)
            : _start(start),
              _count(static_cast<value_type>(type) | (count << 1)) {
        }

        Type type() const {
            return static_cast<Type>(_count & 1);
        }
        capsel_t start() const {
            return _start;
        }
        capsel_t count() const {
            return _count >> 1;
        }

        void to_raw(value_type *raw) const {
            raw[0] = _start;
            raw[1] = _count;
        }

        void format(OStream &os, const FormatSpecs &) const {
            format_to(os, "CRD[{}:{}:{}"_cf, type() == KIF::CapRngDesc::OBJ ? "OBJ" : "MAP",
                      start(), count());
        }

    private:
        value_type _start;
        value_type _count;
    };

    struct DefaultReply {
        xfer_t error;
    } PACKED;

    struct DefaultRequest {
        xfer_t opcode;
    } PACKED;

    struct ExchangeArgs {
        xfer_t bytes;
        unsigned char data[64];
    } PACKED;

    /**
     * System calls
     */
    struct Syscall {
        enum Operation {
            // capability creations
            CREATE_SRV,
            CREATE_SESS,
            CREATE_MGATE,
            CREATE_RGATE,
            CREATE_SGATE,
            CREATE_MAP,
            CREATE_ACT,
            CREATE_SEM,
            ALLOC_EPS,

            // capability operations
            ACTIVATE,
            ACT_CTRL,
            ACT_WAIT,
            DERIVE_MEM,
            DERIVE_KMEM,
            DERIVE_TILE,
            DERIVE_SRV,
            GET_SESS,
            MGATE_REGION,
            RGATE_BUFFER,
            KMEM_QUOTA,
            TILE_QUOTA,
            TILE_SET_QUOTA,
            TILE_SET_PMP,
            TILE_MEM,
            TILE_INFO,
            TILE_RESET,
            SEM_CTRL,

            // capability exchange
            EXCHANGE_SESS,
            EXCHANGE,
            REVOKE,

            // misc
            RESET_STATS,
            NOOP,

            COUNT
        };

        enum ActivityOp {
            VCTRL_INIT,
            VCTRL_START,
            VCTRL_STOP,
        };

        enum SemOp {
            SCTRL_UP,
            SCTRL_DOWN,
        };

        struct CreateSrv : public DefaultRequest {
            xfer_t dst_sel;
            xfer_t rgate_sel;
            xfer_t creator;
            xfer_t namelen;
            char name[MAX_STR_SIZE];
        } PACKED;

        struct CreateSess : public DefaultRequest {
            xfer_t dst_sel;
            xfer_t srv_sel;
            xfer_t creator;
            xfer_t ident;
            xfer_t auto_close;
        } PACKED;

        struct CreateMGate : public DefaultRequest {
            xfer_t dst_sel;
            xfer_t act_sel;
            xfer_t addr;
            xfer_t size;
            xfer_t perms;
        } PACKED;

        struct CreateRGate : public DefaultRequest {
            xfer_t dst_sel;
            xfer_t order;
            xfer_t msgorder;
        } PACKED;

        struct CreateSGate : public DefaultRequest {
            xfer_t dst_sel;
            xfer_t rgate_sel;
            xfer_t label;
            xfer_t credits;
        } PACKED;

        struct CreateMap : public DefaultRequest {
            xfer_t dst_sel;
            xfer_t act_sel;
            xfer_t mgate_sel;
            xfer_t first;
            xfer_t pages;
            xfer_t perms;
        } PACKED;

        struct CreateActivity : public DefaultRequest {
            xfer_t dst_sel;
            xfer_t tile_sel;
            xfer_t kmem_sel;
            xfer_t namelen;
            char name[MAX_STR_SIZE];
        } PACKED;

        struct CreateActivityReply : public DefaultReply {
            xfer_t id;
            xfer_t eps_start;
        } PACKED;

        struct CreateSem : public DefaultRequest {
            xfer_t dst_sel;
            xfer_t value;
        } PACKED;

        struct AllocEP : public DefaultRequest {
            xfer_t dst_sel;
            xfer_t act_sel;
            xfer_t epid;
            xfer_t replies;
        } PACKED;

        struct AllocEPReply : public DefaultReply {
            xfer_t ep;
        } PACKED;

        struct Activate : public DefaultRequest {
            xfer_t ep_sel;
            xfer_t gate_sel;
            xfer_t rbuf_mem;
            xfer_t rbuf_off;
        } PACKED;

        struct ActivityCtrl : public DefaultRequest {
            xfer_t act_sel;
            xfer_t op;
            xfer_t arg;
        } PACKED;

        struct ActivityWait : public DefaultRequest {
            xfer_t event;
            xfer_t act_count;
            xfer_t sels[32];
        } PACKED;

        struct ActivityWaitReply : public DefaultReply {
            xfer_t act_sel;
            xfer_t exitcode;
        } PACKED;

        struct DeriveMem : public DefaultRequest {
            xfer_t act_sel;
            xfer_t dst_sel;
            xfer_t src_sel;
            xfer_t offset;
            xfer_t size;
            xfer_t perms;
        } PACKED;

        struct DeriveKMem : public DefaultRequest {
            xfer_t kmem_sel;
            xfer_t dst_sel;
            xfer_t quota;
        } PACKED;

        struct DeriveTile : public DefaultRequest {
            xfer_t tile_sel;
            xfer_t dst_sel;
            xfer_t eps;
            xfer_t time;
            xfer_t pts;
        } PACKED;

        struct DeriveSrv : public DefaultRequest {
            xfer_t dst_sel;
            xfer_t srv_sel;
            xfer_t sessions;
            xfer_t event;
        } PACKED;

        struct GetSession : public DefaultRequest {
            xfer_t dst_sel;
            xfer_t srv_sel;
            xfer_t act_sel;
            xfer_t sid;
        } PACKED;

        struct MGateRegion : public DefaultRequest {
            xfer_t mgate_sel;
        } PACKED;

        struct MGateRegionReply : public DefaultReply {
            xfer_t global;
            xfer_t size;
        } PACKED;

        struct RGateBuffer : public DefaultRequest {
            xfer_t rgate_sel;
        } PACKED;

        struct RGateBufferReply : public DefaultReply {
            xfer_t order;
            xfer_t msg_order;
        } PACKED;

        struct KMemQuota : public DefaultRequest {
            xfer_t kmem_sel;
        } PACKED;

        struct KMemQuotaReply : public DefaultReply {
            xfer_t id;
            xfer_t total;
            xfer_t left;
        } PACKED;

        struct TileQuota : public DefaultRequest {
            xfer_t tile_sel;
        } PACKED;

        struct TileQuotaReply : public DefaultReply {
            xfer_t eps_id;
            xfer_t eps_total;
            xfer_t eps_left;
            xfer_t time_id;
            xfer_t time_total;
            xfer_t time_left;
            xfer_t pts_id;
            xfer_t pts_total;
            xfer_t pts_left;
        } PACKED;

        struct TileSetQuota : public DefaultRequest {
            xfer_t tile_sel;
            xfer_t time;
            xfer_t pts;
        } PACKED;

        struct TileSetPMP : public DefaultRequest {
            xfer_t tile_sel;
            xfer_t mgate_sel;
            xfer_t epid;
            xfer_t overwrite;
        } PACKED;

        struct TileReset : public DefaultRequest {
            xfer_t tile_sel;
            xfer_t mux_mem_sel;
            xfer_t ep_count;
        } PACKED;

        enum MuxType {
            NONE,
            TILE_MUX,
            LINUX,
            ACCEL,
        };

        struct TileInfo : public DefaultRequest {
            xfer_t tile_sel;
        } PACKED;

        struct TileInfoReply : public DefaultReply {
            xfer_t type;
            xfer_t id;
            xfer_t desc;
            xfer_t ep_count;
        } PACKED;

        struct TileMem : public DefaultRequest {
            xfer_t dst_sel;
            xfer_t tile_sel;
        } PACKED;

        struct SemCtrl : public DefaultRequest {
            xfer_t sem_sel;
            xfer_t op;
        } PACKED;

        struct Exchange : public DefaultRequest {
            xfer_t act_sel;
            xfer_t own_caps[2];
            xfer_t other_sel;
            xfer_t obtain;
        } PACKED;

        struct ExchangeSess : public DefaultRequest {
            xfer_t act_sel;
            xfer_t sess_sel;
            xfer_t caps[2];
            ExchangeArgs args;
            xfer_t obtain;
        } PACKED;

        struct ExchangeSessReply : public DefaultReply {
            ExchangeArgs args;
        } PACKED;

        struct Revoke : public DefaultRequest {
            xfer_t act_sel;
            xfer_t caps[2];
            xfer_t own;
        } PACKED;

        struct ResetStats : public DefaultRequest {
        } PACKED;

        struct Noop : public DefaultRequest {
        } PACKED;
    };

    /**
     * Service calls
     */
    struct Service {
        enum Operation {
            OPEN,
            DERIVE_CRT,
            OBTAIN,
            DELEGATE,
            CLOSE,
            SHUTDOWN
        };

        struct Open : public DefaultRequest {
            xfer_t arglen;
            char arg[MAX_STR_SIZE];
        } PACKED;

        struct OpenReply : public DefaultReply {
            xfer_t sess;
            xfer_t ident;
        } PACKED;

        struct DeriveCreator : public DefaultRequest {
            xfer_t sessions;
        } PACKED;

        struct DeriveCreatorReply : public DefaultReply {
            xfer_t creator;
            xfer_t sgate_sel;
        } PACKED;

        struct ExchangeData {
            xfer_t caps[2];
            ExchangeArgs args;
        } PACKED;

        struct Exchange : public DefaultRequest {
            xfer_t sess;
            ExchangeData data;
        } PACKED;

        struct ExchangeReply : public DefaultReply {
            ExchangeData data;
        } PACKED;

        struct Close : public DefaultRequest {
            xfer_t sess;
        } PACKED;

        struct Shutdown : public DefaultRequest {
        } PACKED;
    };

    /**
     * Upcalls
     */
    struct Upcall {
        enum Operation {
            DERIVE_SRV,
            ACTIVITY_WAIT,
        };

        struct DefaultUpcall : public DefaultRequest {
            xfer_t event;
        } PACKED;

        struct ActivityWait : public DefaultUpcall {
            xfer_t error;
            xfer_t act_sel;
            xfer_t exitcode;
        } PACKED;
    };
};

}
