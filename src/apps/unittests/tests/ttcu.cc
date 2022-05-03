/*
 * Copyright (C) 2015-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#if defined(__host__)
#    include <base/Env.h>

#    include <m3/Test.h>
#    include <m3/com/GateStream.h>
#    include <m3/com/MemGate.h>
#    include <m3/com/RecvGate.h>
#    include <m3/stream/Standard.h>

#    include <sys/mman.h>

#    include "../unittests.h"

using namespace m3;

static void *map_page() {
    void *addr = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if(addr == MAP_FAILED) {
        exitmsg("mmap failed. Skipping test.");
        return nullptr;
    }
    return addr;
}
static void unmap_page(void *addr) {
    munmap(addr, 0x1000);
}

static void dmacmd(const void *data, size_t len, epid_t ep, size_t offset, size_t length, int op) {
    m3::TCU &tcu = m3::TCU::get();
    tcu.set_cmd(m3::TCU::CMD_ADDR, reinterpret_cast<word_t>(data));
    tcu.set_cmd(m3::TCU::CMD_SIZE, len);
    tcu.set_cmd(m3::TCU::CMD_EPID, ep);
    tcu.set_cmd(m3::TCU::CMD_OFFSET, offset);
    tcu.set_cmd(m3::TCU::CMD_LENGTH, length);
    tcu.set_cmd(m3::TCU::CMD_REPLYLBL, 0);
    tcu.set_cmd(m3::TCU::CMD_REPLY_EPID, 0);
    tcu.set_cmd(m3::TCU::CMD_CTRL,
                static_cast<word_t>(op << 3) | m3::TCU::CTRL_START | m3::TCU::CTRL_DEL_REPLY_CAP);
    tcu.exec_command();
}

static void cmds_read() {
    EP *rcvep = Activity::own().epmng().acquire();
    EP *sndep = Activity::own().epmng().acquire();
    TCU &tcu = TCU::get();

    void *addr = map_page();
    if(!addr)
        return;

    const size_t datasize = sizeof(word_t) * 4;
    word_t *data = reinterpret_cast<word_t *>(addr);
    data[0] = 1234;
    data[1] = 5678;
    data[2] = 1122;
    data[3] = 3344;

    cout << "-- Test errors --\n";
    {
        tcu.configure(sndep->id(), reinterpret_cast<word_t>(data), MemGate::R, env()->tile_id,
                      rcvep->id(), datasize, 0);

        dmacmd(nullptr, 0, sndep->id(), 0, datasize, TCU::WRITE);
        WVASSERTEQ(tcu.get_cmd(TCU::CMD_ERROR), static_cast<word_t>(Errors::NO_PERM));

        dmacmd(nullptr, 0, sndep->id(), 0, datasize + 1, TCU::READ);
        WVASSERTEQ(tcu.get_cmd(TCU::CMD_ERROR), static_cast<word_t>(Errors::INV_ARGS));

        dmacmd(nullptr, 0, sndep->id(), datasize, 0, TCU::READ);
        WVASSERTEQ(tcu.get_cmd(TCU::CMD_ERROR), static_cast<word_t>(Errors::INV_ARGS));

        dmacmd(nullptr, 0, sndep->id(), sizeof(word_t), datasize, TCU::READ);
        WVASSERTEQ(tcu.get_cmd(TCU::CMD_ERROR), static_cast<word_t>(Errors::INV_ARGS));
    }

    cout << "-- Test reading --\n";
    {
        tcu.configure(sndep->id(), reinterpret_cast<word_t>(data), MemGate::R, env()->tile_id,
                      rcvep->id(), datasize, 0);

        word_t buf[datasize / sizeof(word_t)];

        dmacmd(buf, datasize, sndep->id(), 0, datasize, TCU::READ);
        WVASSERTEQ(tcu.get_cmd(TCU::CMD_ERROR), static_cast<word_t>(Errors::NONE));
        for(size_t i = 0; i < 4; ++i)
            WVASSERTEQ(buf[i], data[i]);
    }

    unmap_page(addr);
    tcu.configure(sndep->id(), 0, 0, 0, 0, 0, 0);

    Activity::own().epmng().release(sndep, true);
    Activity::own().epmng().release(rcvep, true);
}

static void cmds_write() {
    EP *rcvep = Activity::own().epmng().acquire();
    EP *sndep = Activity::own().epmng().acquire();
    TCU &tcu = TCU::get();

    void *addr = map_page();
    if(!addr)
        return;

    cout << "-- Test errors --\n";
    {
        word_t data[] = {1234, 5678, 1122, 3344};
        tcu.configure(sndep->id(), reinterpret_cast<word_t>(addr), MemGate::W, env()->tile_id,
                      rcvep->id(), sizeof(data), 0);

        dmacmd(nullptr, 0, sndep->id(), 0, sizeof(data), TCU::READ);
        WVASSERTEQ(tcu.get_cmd(TCU::CMD_ERROR), static_cast<word_t>(Errors::NO_PERM));
    }

    cout << "-- Test writing --\n";
    {
        word_t data[] = {1234, 5678, 1122, 3344};
        tcu.configure(sndep->id(), reinterpret_cast<word_t>(addr), MemGate::W, env()->tile_id,
                      rcvep->id(), sizeof(data), 0);

        dmacmd(data, sizeof(data), sndep->id(), 0, sizeof(data), TCU::WRITE);
        WVASSERTEQ(tcu.get_cmd(TCU::CMD_ERROR), static_cast<word_t>(Errors::NONE));
        volatile const word_t *words = reinterpret_cast<const word_t *>(addr);
        for(size_t i = 0; i < sizeof(data) / sizeof(data[0]); ++i)
            WVASSERTEQ(static_cast<word_t>(words[i]), data[i]);
    }

    unmap_page(addr);
    tcu.configure(sndep->id(), 0, 0, 0, 0, 0, 0);

    Activity::own().epmng().release(sndep, true);
    Activity::own().epmng().release(rcvep, true);
}

static void mem_sync() {
    static xfer_t data[4];

    MemGate mem = m3::MemGate::create_global(0x4000, m3::MemGate::RWX);
    MemGate gate = MemGate::bind(mem.sel());

    cout << "-- Test read sync --\n";
    {
        write_vmsg(gate, 0, 1, 2, 3, 4);
        gate.read(data, sizeof(data), 0);
        WVASSERTEQ(data[0], 1u);
        WVASSERTEQ(data[1], 2u);
        WVASSERTEQ(data[2], 3u);
        WVASSERTEQ(data[3], 4u);
    }
}

static void mem_derive() {
    static xfer_t test[6] = {0};

    MemGate mem = m3::MemGate::create_global(0x4000, m3::MemGate::RWX);
    MemGate gate = MemGate::bind(mem.sel());
    write_vmsg(gate, 0, 1, 2, 3, 4);

    cout << "-- Test derive --\n";
    {
        gate.read(test, sizeof(xfer_t) * 4, 0);

        WVASSERTEQ(test[0], 1u);
        WVASSERTEQ(test[1], 2u);
        WVASSERTEQ(test[2], 3u);
        WVASSERTEQ(test[3], 4u);
        WVASSERTEQ(test[4], 0u);

        MemGate sub = gate.derive(4 * sizeof(xfer_t), sizeof(xfer_t), MemGate::RWX);
        write_vmsg(sub, 0, 5);
        gate.read(test, sizeof(xfer_t) * 5, 0);

        WVASSERTEQ(test[0], 1u);
        WVASSERTEQ(test[1], 2u);
        WVASSERTEQ(test[2], 3u);
        WVASSERTEQ(test[3], 4u);
        WVASSERTEQ(test[4], 5u);
    }

    cout << "-- Test wrong derive --\n";
    {
        MemGate sub = gate.derive(4 * sizeof(xfer_t), sizeof(xfer_t), MemGate::R);
        sub.read(test, sizeof(xfer_t), 0);
        WVASSERTEQ(test[0], 5u);

        WVASSERTERR(Errors::NO_PERM, [&sub] {
            write_vmsg(sub, 0, 8);
        });
    }
}

void ttcu() {
    RUN_TEST(cmds_read);
    RUN_TEST(cmds_write);
    RUN_TEST(mem_sync);
    RUN_TEST(mem_derive);
}

#endif
