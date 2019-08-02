/*
 * Copyright (C) 2015-2016, Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <m3/com/SendGate.h>
#include <m3/com/MemGate.h>
#include <m3/com/RecvGate.h>
#include <m3/com/GateStream.h>
#include <m3/stream/Standard.h>

using namespace m3;

static constexpr size_t SIZE = 64;

static unsigned int some_data[SIZE];
static unsigned int some_data_ctrl[SIZE];

static void check_result() {
    int errors = 0;
    for(size_t i = 0; i < ARRAY_SIZE(some_data); ++i) {
        if(some_data_ctrl[i] != some_data[i]) {
            cout << "received[" << i << "]: "
                 << fmt(some_data_ctrl[i], "#0X", 8) << " != " << fmt(some_data[i], "#0X", 8) << "\n";
            errors++;
        }
    }
    if(errors == 0)
        cout << "Result correct!\n";
    else
        cout << "Result NOT correct!\n";
}

int main() {
    for(size_t i = 0; i < ARRAY_SIZE(some_data); ++i)
        some_data[i] = i;
    memset(some_data_ctrl, 0, sizeof(some_data_ctrl));

    cout << "Requesting memory...\n";
    MemGate mem = MemGate::create_global(sizeof(some_data) * 8, MemGate::RW);

    cout << "Writing to it and reading it back...\n";
    mem.write(some_data, sizeof(some_data), 2 * sizeof(some_data));
    mem.read(some_data_ctrl, sizeof(some_data_ctrl), 2 * sizeof(some_data));

    check_result();

    cout << "Deriving memory...\n";
    MemGate submem = mem.derive(0x20, 4 * sizeof(some_data), MemGate::RWX);

    cout << "Writing to it and reading it back...\n";
    submem.write(some_data, sizeof(some_data), 2 * sizeof(some_data));
    submem.read(some_data_ctrl, sizeof(some_data_ctrl), 2 * sizeof(some_data));

    check_result();
    return 0;
}
