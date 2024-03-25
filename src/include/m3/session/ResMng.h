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

#pragma once

#include <base/Panic.h>

#include <m3/Exception.h>
#include <m3/com/GateStream.h>
#include <m3/com/OpCodes.h>
#include <m3/com/SendGate.h>
#include <m3/tiles/ChildActivity.h>
#include <m3/tiles/OwnActivity.h>

#include <memory>
#include <string_view>

namespace m3 {

class ResMngChild;

class ResMng {
    friend class ResMngChild;

public:
    class ResMngException : public m3::Exception {
    public:
        explicit ResMngException(Errors::Code code, opcodes::ResMng::Operation op) noexcept
            : m3::Exception(code),
              _op(op) {
        }

        opcodes::ResMng::Operation operation() const {
            return _op;
        }

        const char *what() const noexcept override {
            static const char *names[] = {
                "REG_SERV",  "UNREG_SERV", "OPEN_SESS", "CLOSE_SESS", "ADD_CHILD",
                "REM_CHILD", "ALLOC_MEM",  "FREE_MEM",  "ALLOC_TILE", "FREE_TILE",
                "USE_RGATE", "USE_SGATE",  "USE_SEM",
            };

            OStringStream os(msg_buf, sizeof(msg_buf));
            format_to(os, "The resource manager operation {} failed: {}"_cf, names[_op], code());
            return msg_buf;
        }

    private:
        opcodes::ResMng::Operation _op;
    };

    explicit ResMng(capsel_t resmng) noexcept : _sgate(SendGate::bind(resmng)) {
    }

    capsel_t sel() const noexcept {
        return _sgate.sel();
    }

    std::unique_ptr<ResMngChild> clone(ChildActivity &act, capsel_t sgate_sel,
                                       const std::string_view &name);

    void reg_service(capsel_t dst, capsel_t sgate, const std::string_view &name, size_t sessions) {
        GateIStream reply =
            send_receive_vmsg(_sgate, opcodes::ResMng::REG_SERV, dst, sgate, name, sessions);
        retrieve_result(opcodes::ResMng::REG_SERV, reply);
    }

    void unreg_service(capsel_t sel) {
        GateIStream reply = send_receive_vmsg(_sgate, opcodes::ResMng::UNREG_SERV, sel);
        retrieve_result(opcodes::ResMng::UNREG_SERV, reply);
    }

    void open_sess(capsel_t dst, const std::string_view &name) {
        GateIStream reply = send_receive_vmsg(_sgate, opcodes::ResMng::OPEN_SESS, dst, name);
        retrieve_result(opcodes::ResMng::OPEN_SESS, reply);
    }

    void close_sess(capsel_t sel) {
        GateIStream reply = send_receive_vmsg(_sgate, opcodes::ResMng::CLOSE_SESS, sel);
        retrieve_result(opcodes::ResMng::CLOSE_SESS, reply);
    }

    void alloc_mem(capsel_t sel, size_t size, int perm) {
        GateIStream reply = send_receive_vmsg(_sgate, opcodes::ResMng::ALLOC_MEM, sel, size, perm);
        retrieve_result(opcodes::ResMng::ALLOC_MEM, reply);
    }

    void free_mem(capsel_t sel) {
        GateIStream reply = send_receive_vmsg(_sgate, opcodes::ResMng::FREE_MEM, sel);
        retrieve_result(opcodes::ResMng::FREE_MEM, reply);
    }

    TileDesc alloc_tile(capsel_t sel, const TileDesc &desc, bool init, bool inherit_pmp) {
        GateIStream reply = send_receive_vmsg(_sgate, opcodes::ResMng::ALLOC_TILE, sel,
                                              desc.value(), init, inherit_pmp);
        retrieve_result(opcodes::ResMng::ALLOC_TILE, reply);
        TileDesc::value_t res;
        TileId::raw_t tileid;
        reply >> tileid >> res;
        return TileDesc(res);
    }

    void free_tile(capsel_t sel) {
        GateIStream reply = send_receive_vmsg(_sgate, opcodes::ResMng::FREE_TILE, sel);
        retrieve_result(opcodes::ResMng::FREE_TILE, reply);
    }

    std::pair<uint, uint> use_rgate(capsel_t sel, const std::string_view &name) {
        GateIStream reply = send_receive_vmsg(_sgate, opcodes::ResMng::USE_RGATE, sel, name);
        retrieve_result(opcodes::ResMng::USE_SEM, reply);
        uint order, msg_order;
        reply >> order >> msg_order;
        return std::make_pair(order, msg_order);
    }

    void use_sgate(capsel_t sel, const std::string_view &name) {
        GateIStream reply = send_receive_vmsg(_sgate, opcodes::ResMng::USE_SGATE, sel, name);
        retrieve_result(opcodes::ResMng::USE_SEM, reply);
    }

    void use_sem(capsel_t sel, const std::string_view &name) {
        GateIStream reply = send_receive_vmsg(_sgate, opcodes::ResMng::USE_SEM, sel, name);
        retrieve_result(opcodes::ResMng::USE_SEM, reply);
    }

    void use_mod(capsel_t sel, const std::string_view &name) {
        GateIStream reply = send_receive_vmsg(_sgate, opcodes::ResMng::USE_MOD, sel, name);
        retrieve_result(opcodes::ResMng::USE_MOD, reply);
    }

private:
    void clone(actid_t act_id, capsel_t act_sel, capsel_t tile_sel, capsel_t kmem_sel,
               capsel_t sgate_sel, const std::string_view &name) {
        GateIStream reply = send_receive_vmsg(_sgate, opcodes::ResMng::ADD_CHILD, act_id, act_sel,
                                              tile_sel, kmem_sel, sgate_sel, name);
        retrieve_result(opcodes::ResMng::ADD_CHILD, reply);
    }

    void retrieve_result(opcodes::ResMng::Operation op, GateIStream &reply) {
        Errors::Code res;
        reply >> res;
        if(res != Errors::SUCCESS) {
            // ensure that we ACK the message before throwing the exception, which might trigger
            // other actions that want to reuse the default RecvGate.
            reply.finish();
            throw ResMngException(res, op);
        }
    }

    SendGate _sgate;
};

class ResMngChild {
public:
    explicit ResMngChild(capsel_t scap, capsel_t act_sel)
        : scap(SendCap::bind(scap)),
          act_sel(act_sel) {
    }
    ~ResMngChild() {
        send_receive_vmsg(Activity::own().resmng()->_sgate, opcodes::ResMng::REM_CHILD, act_sel);
    }

    ResMngChild(ResMngChild &&r) : scap(std::move(r.scap)), act_sel(r.act_sel) {
    }

    capsel_t sel() const {
        return scap.sel();
    }

private:
    SendCap scap;
    capsel_t act_sel;
};

inline std::unique_ptr<ResMngChild> ResMng::clone(ChildActivity &act, capsel_t sgate_sel,
                                                  const std::string_view &name) {
    clone(act.id(), act.sel(), act.tile()->sel(), act.kmem()->sel(), sgate_sel, name);
    return std::make_unique<ResMngChild>(sgate_sel, act.sel());
}

}
