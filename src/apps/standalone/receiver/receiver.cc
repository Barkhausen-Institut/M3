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
#include <base/stream/Serial.h>
#include <base/time/Instant.h>
#include <base/util/Util.h>

#include "../assert.h"
#include "../tcuif.h"

using namespace m3;

static constexpr epid_t REP = TCU::FIRST_USER_EP;

static uint8_t rbuf[8 * 64];

int main() {
    kernel::TCU::init();

    size_t size = nextlog2<sizeof(rbuf)>::val;
    uintptr_t rbuf_addr = reinterpret_cast<uintptr_t>(rbuf);
    kernel::TCU::config_recv(REP, rbuf_addr, size, size - nextlog2<8>::val, REP + 1);

    MsgBuf reply;
    reply.cast<uint64_t>() = 0;

    logln("Hello World from receiver!"_cf);

    for(int count = 0; count < 700000; ++count) {
        // wait for message
        const TCU::Message *rmsg;
        while((rmsg = kernel::TCU::fetch_msg(REP, rbuf_addr)) == nullptr)
            ;
        ASSERT_EQ(rmsg->label, 0x1234);

        // send reply
        ASSERT_EQ(kernel::TCU::reply(REP, reply, rbuf_addr, rmsg), Errors::SUCCESS);
        reply.cast<uint64_t>() += 1;
    }

    // give the other tiles some time
    auto end = TimeInstant::now() + TimeDuration::from_millis(10);
    while(TimeInstant::now() < end)
        ;

    // for the test infrastructure
    logln("Shutting down"_cf);
    return 0;
}
