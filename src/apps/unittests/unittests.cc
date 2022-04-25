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

#include <base/Common.h>

#include <m3/vfs/VFS.h>
#include <m3/stream/Standard.h>
#include <m3/tiles/Activity.h>

#include "unittests.h"

using namespace m3;

int failed;

int main() {
    RUN_SUITE(tsems);
#if defined(__host__)
    RUN_SUITE(ttcu);
#endif
    RUN_SUITE(tenvvars);
    RUN_SUITE(tfsmeta);
    RUN_SUITE(tfs);
    RUN_SUITE(tbitfield);
    RUN_SUITE(theap);
    RUN_SUITE(tnonblock);
    RUN_SUITE(tstream);
    RUN_SUITE(tpipe);
    RUN_SUITE(tstring);
    RUN_SUITE(tsgate);

    if(failed > 0)
        cout << "\033[1;31m" << failed << " tests failed\033[0;m\n";
    else
        cout << "\033[1;32mAll tests successful!\033[0;m\n";
    return 0;
}
