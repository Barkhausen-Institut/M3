/*
 * Copyright (C) 2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019-2021 Nils Asmussen, Barkhausen Institut
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
#include <base/time/Profile.h>
#include <base/Panic.h>

#include <m3/vfs/FileRef.h>
#include <m3/Test.h>

#include "../cppbenchs.h"

using namespace m3;

alignas(PAGE_SIZE) static char buf[8192];

NOINLINE static void open_close() {
    Profile pr(50, 10);

    WVPERF("open-close", pr.run<CycleInstant>([] {
        FileRef file("/data/2048k.txt", FILE_R);
    }));
}

NOINLINE static void stat() {
    Profile pr(50, 10);

    WVPERF(__func__, pr.run<CycleInstant>([] {
        FileInfo info;
        VFS::stat("/data/2048k.txt", info);
    }));
}

NOINLINE static void mkdir_rmdir() {
    Profile pr(50, 10);

    WVPERF(__func__, pr.run<CycleInstant>([] {
        VFS::mkdir("/newdir", 0755);
        VFS::rmdir("/newdir");
    }));
}

NOINLINE static void link_unlink() {
    Profile pr(50, 10);

    WVPERF(__func__, pr.run<CycleInstant>([] {
        VFS::link("/large.txt", "/newlarge.txt");
        VFS::unlink("/newlarge.txt");
    }));
}

NOINLINE static void read() {
    Profile pr(2, 1);

    WVPERF("read 2 MiB file with 8K buf", pr.run<CycleInstant>([] {
        FileRef file("/data/2048k.txt", FILE_R);

        ssize_t amount;
        while((amount = file->read(buf, sizeof(buf))) > 0)
            ;
    }));
}

NOINLINE static void write() {
    const size_t SIZE = 2 * 1024 * 1024;
    Profile pr(2, 1);

    WVPERF("write 2 MiB file with 8K buf", pr.run<CycleInstant>([] {
        FileRef file("/newfile", FILE_W | FILE_TRUNC | FILE_CREATE);

        size_t total = 0;
        while(total < SIZE) {
            ssize_t amount = file->write(buf, sizeof(buf));
            total += static_cast<size_t>(amount);
        }
    }));
}

NOINLINE static void copy() {
    Profile pr(2, 1);

    WVPERF("copy 2 MiB file with 8K buf", pr.run<CycleInstant>([] {
        FileRef in("/data/2048k.txt", FILE_R);
        FileRef out("/newfile", FILE_W | FILE_TRUNC | FILE_CREATE);

        ssize_t count;
        while((count = in->read(buf, sizeof(buf))) > 0)
            out->write_all(buf, static_cast<size_t>(count));
    }));
}

void bregfile() {
    RUN_BENCH(open_close);
    RUN_BENCH(stat);
    RUN_BENCH(mkdir_rmdir);
    RUN_BENCH(link_unlink);
    RUN_BENCH(read);
    RUN_BENCH(write);
    RUN_BENCH(copy);
}
