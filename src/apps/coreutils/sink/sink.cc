/*
 * Copyright (C) 2016-2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <m3/stream/Standard.h>
#include <m3/Exception.h>

using namespace m3;

alignas(64) static char buffer[8192];

static void read(FStream &in) {
    while(in.read(buffer, sizeof(buffer)) > 0)
        ;
}

int main(int argc, char **argv) {
    if(argc == 1)
        read(cin);
    else {
        for(int i = 1; i < argc; ++i) {
            try {
                FStream input(argv[i], FILE_R);
                read(input);
            }
            catch(const Exception &e) {
                errmsg("open failed: " << e.what());
            }
        }
    }
    return 0;
}
