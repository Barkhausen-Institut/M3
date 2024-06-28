/*
 * Copyright (C) 2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
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
#include <base/stream/Serial.h>
#include <base/time/Instant.h>
#include <base/TCU.h>

#include "../assert.h"
#include "../tcuif.h"

#include "../tiles.h"
//#include "../tiles_bic1.h"

using namespace m3;

#define CLKFREQ_MHZ 100

static constexpr epid_t DSTEP = TCU::FIRST_USER_EP;
static constexpr epid_t SEP = TCU::FIRST_USER_EP;
static constexpr epid_t REP = TCU::FIRST_USER_EP + 1;

static constexpr size_t TESTDATA_SIZE = 64; //max. 64, limited by TCU msg size
static constexpr size_t ITER_MAX = 500000;

TileId local_tile;
TileId remote_tile = TILE_IDS[Tile::T0];    //take T0 as remote

static uint64_t rbuf[TESTDATA_SIZE];



cycles_t nanos_diff_to_cycles(uint64_t start_nanos, uint64_t end_nanos) {
    return (end_nanos-start_nanos)*CLKFREQ_MHZ/1000;
}


cycles_t test_msg_send(size_t size_in) {
    uint64_t start_nanos, end_nanos;

    //prepare send data
    MsgBuf msg;
    auto *msg_data = &msg.cast<uint64_t>();
    for (size_t i=0; i<size_in; ++i)
        msg_data[i] = i + 1;
    msg.set_size(size_in * sizeof(uint64_t));

    const size_t TESTMSG_SIZE = size_in * sizeof(uint64_t) + sizeof(TCU::Header);
    unsigned msgsize_pwr2 = m3::getnextlog2(TESTMSG_SIZE);
    kernel::TCU::config_send(SEP, 0x1234, remote_tile, DSTEP, msgsize_pwr2, 1);
    
    uintptr_t rbuf_addr = reinterpret_cast<uintptr_t>(rbuf);
    //recv EP: no replies
    kernel::TCU::config_recv(REP, rbuf_addr, msgsize_pwr2, msgsize_pwr2, TCU::NO_REPLIES);


    start_nanos = kernel::TCU::nanotime();
    for (size_t count=0; count<ITER_MAX; ++count) {
        //send message
        ASSERT_EQ(kernel::TCU::send(SEP, msg, 0x2222, REP), Errors::SUCCESS);

        //wait for reply
        const TCU::Message *rmsg;
        while((rmsg = kernel::TCU::fetch_msg(REP, rbuf_addr)) == nullptr);
        ASSERT_EQ(rmsg->label, 0x2222);

        //ack reply
        ASSERT_EQ(kernel::TCU::ack_msg(REP, rbuf_addr, rmsg), Errors::SUCCESS);

        //logln("send iter {}"_cf, count);
    }
    end_nanos = kernel::TCU::nanotime();

    return nanos_diff_to_cycles(start_nanos, end_nanos)/ITER_MAX;
}


int main() {
    //check on which tile this code runs
    //this code should not run on T0 because this is used to write to
    local_tile = TileId::from_raw(env()->tile_id);
    if (local_tile.raw() == TILE_IDS[Tile::T0].raw()) {
        logln("This is {}. Do not run this code on T0!\n"_cf, local_tile);
        logln("Shutting down"_cf);
        return 0;
    }


    logln("This is {}. Starting measurement with {}.\n"_cf, local_tile, remote_tile);
    logln("#elements: {}, #iterations: {}"_cf, TESTDATA_SIZE, ITER_MAX);
    cycles_t time_result;
    time_result = test_msg_send(TESTDATA_SIZE);
    logln("\nResult #cycles for send msg: {}"_cf, time_result);

    return 0;
}
