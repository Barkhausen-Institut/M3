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

static constexpr epid_t REP = TCU::FIRST_USER_EP;
static constexpr epid_t REP2 = TCU::FIRST_USER_EP+8;

static constexpr size_t TESTDATA_SIZE = 64; //max. 64, limited by TCU msg size
static constexpr size_t ITER_MAX = 500000;
static constexpr size_t NUM_SENDERS = 3;
static constexpr size_t NUMLOG2_SENDERS = m3::getnextlog2(NUM_SENDERS);

TileId local_tile;

static uint64_t rbuf[(TESTDATA_SIZE+sizeof(TCU::Header))*(1<<NUMLOG2_SENDERS)];



cycles_t nanos_diff_to_cycles(uint64_t start_nanos, uint64_t end_nanos) {
    return (end_nanos-start_nanos)*CLKFREQ_MHZ/1000;
}


cycles_t test_msg_recv(size_t size_in) {
    uint64_t start_nanos, end_nanos;

    uintptr_t rbuf_addr = reinterpret_cast<uintptr_t>(rbuf);
    const size_t TESTMSG_SIZE = size_in * sizeof(uint64_t) + sizeof(TCU::Header);
    unsigned msgsize_pwr2 = m3::getnextlog2(TESTMSG_SIZE);
    //recv EP: create as many slots as there are senders
    kernel::TCU::config_recv(REP, rbuf_addr, msgsize_pwr2+NUMLOG2_SENDERS, msgsize_pwr2, REP+1);

    //prepare reply data
    MsgBuf reply;
    auto *reply_data = &reply.cast<uint64_t>();
    for(size_t i = 0; i < size_in; ++i)
        reply_data[i] = size_in + i + 1;
    reply.set_size(size_in * sizeof(uint64_t));


    start_nanos = kernel::TCU::nanotime();
    for (size_t count=0; count<(ITER_MAX*NUM_SENDERS); ++count) {
        //wait for message
        const TCU::Message *rmsg;
        while((rmsg = kernel::TCU::fetch_msg(REP, rbuf_addr)) == nullptr);
        ASSERT_EQ(rmsg->label, 0x1234);

        // send reply
        ASSERT_EQ(kernel::TCU::reply(REP, reply, rbuf_addr, rmsg), Errors::SUCCESS);

        //if (count % ((ITER_MAX*NUM_SENDERS)/10) == 0)
        //    logln("Iter {}"_cf, count);
    }
    end_nanos = kernel::TCU::nanotime();

    return nanos_diff_to_cycles(start_nanos, end_nanos)/ITER_MAX/NUM_SENDERS;
}



int main() {
    //check on which tile this code runs
    //this code should only run on T0 because this is the receiver
    local_tile = TileId::from_raw(env()->tile_id);
    if (local_tile.raw() != TILE_IDS[Tile::T0].raw()) {
        logln("This is {}. Do not run this code on any tile except T0!\n"_cf, local_tile);
        logln("Shutting down"_cf);
        return 0;
    }


    logln("This is {}. Starting measurement with {} sender tiles.\n"_cf, local_tile, NUM_SENDERS);
    logln("#elements: {}, #iterations: {}"_cf, TESTDATA_SIZE, ITER_MAX);
    cycles_t time_result;
    time_result = test_msg_recv(TESTDATA_SIZE);
    logln("\nResult #cycles for recv msg: {}"_cf, time_result);

    //give the other tiles some time to finish
    auto end = TimeInstant::now() + TimeDuration::from_millis(1000);
    while(TimeInstant::now() < end);

    logln(""_cf);
    logln("Shutting down"_cf);
    return 0;
}
