/*
 * Copyright (C) 2015-2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <base/stream/IStringStream.h>

#include <m3/com/MemGate.h>
#include <m3/com/SendGate.h>
#include <m3/com/RecvGate.h>
#include <m3/com/GateStream.h>
#include <m3/stream/Standard.h>
#include <m3/pes/VPE.h>

using namespace m3;

struct Worker {
    MemGate submem;
    SendGate sgate;
    Reference<PE> pe;
    VPE vpe;

    Worker(RecvGate &rgate, MemGate &mem, size_t offset, size_t size)
        : submem(mem.derive(offset, size)),
          sgate(SendGate::create(&rgate, SendGateArgs().credits(1))),
          pe(PE::alloc("child")),
          vpe(pe, "worker") {
        vpe.delegate_obj(submem.sel());
        vpe.fds(VPE::self().fds());
        vpe.obtain_fds();
    }
};

static const size_t BUF_SIZE    = 4096;

int main(int argc, char **argv) {
    size_t memPerVPE = 1024 * 1024;
    size_t vpes = 2;
    if(argc > 1)
        vpes = IStringStream::read_from<size_t>(argv[1]);
    if(argc > 2)
        memPerVPE = IStringStream::read_from<size_t>(argv[2]);

    const size_t AREA_SIZE    = vpes * memPerVPE;
    const size_t SUBAREA_SIZE = AREA_SIZE / vpes;

    RecvGate rgate = RecvGate::create(getnextlog2(vpes * 64), nextlog2<64>::val);
    MemGate mem = MemGate::create_global(AREA_SIZE, MemGate::RW);

    // create worker
    Worker **worker = new Worker*[vpes];
    for(size_t i = 0; i < vpes; ++i)
        worker[i] = new Worker(rgate, mem, static_cast<size_t>(i) * SUBAREA_SIZE, SUBAREA_SIZE);

    // write data into memory
    for(size_t i = 0; i < vpes; ++i) {
        MemGate &vpemem = worker[i]->submem;
        worker[i]->vpe.run([&vpemem, SUBAREA_SIZE] {
            uint *buffer = new uint[BUF_SIZE / sizeof(uint)];
            size_t rem = SUBAREA_SIZE;
            size_t offset = 0;
            while(rem > 0) {
                for(size_t i = 0; i < BUF_SIZE / sizeof(uint); ++i)
                    buffer[i] = i;
                vpemem.write(buffer, BUF_SIZE, offset);
                offset += BUF_SIZE;
                rem -= BUF_SIZE;
            }
            cout << "Memory initialization of " << SUBAREA_SIZE << " bytes finished\n";
            return 0;
        });
    }

    // wait for all workers
    for(size_t i = 0; i < vpes; ++i)
        worker[i]->vpe.wait();

    // now build the checksum
    for(size_t i = 0; i < vpes; ++i) {
        worker[i]->vpe.delegate_obj(worker[i]->sgate.sel());
        MemGate &vpemem = worker[i]->submem;
        SendGate &vpegate = worker[i]->sgate;
        worker[i]->vpe.run([&vpemem, &vpegate, SUBAREA_SIZE] {
            uint *buffer = new uint[BUF_SIZE / sizeof(uint)];

            uint checksum = 0;
            size_t rem = SUBAREA_SIZE;
            size_t offset = 0;
            while(rem > 0) {
                vpemem.read(buffer, BUF_SIZE, offset);
                for(size_t i = 0; i < BUF_SIZE / sizeof(uint); ++i)
                    checksum += buffer[i];
                offset += BUF_SIZE;
                rem -= BUF_SIZE;
            }

            cout << "Checksum for sub area finished\n";
            send_vmsg(vpegate, checksum);
            return 0;
        });
    }

    // reduce
    uint checksum = 0;
    for(size_t i = 0; i < vpes; ++i) {
        uint vpechksum;
        receive_vmsg(rgate, vpechksum);
        checksum += vpechksum;
    }

    cout << "Checksum: " << checksum << "\n";

    for(size_t i = 0; i < vpes; ++i) {
        worker[i]->vpe.wait();
        delete worker[i];
    }
    return 0;
}
