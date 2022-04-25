/*
 * Copyright (C) 2015-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019 Nils Asmussen, Barkhausen Institut
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

#include <base/stream/OStringStream.h>

#include <m3/stream/Standard.h>
#include <m3/vfs/VFS.h>

using namespace m3;

static FileRef<GenericFile> open_man(const char *arg1) {
    FileInfo info;
    if(VFS::try_stat(arg1, info) == Errors::NONE)
        return VFS::open(arg1, FILE_R);

    OStringStream os;
    os << "/man/" << arg1 << ".1";
    return VFS::open(os.str(), FILE_R);
}

int main(int argc, char **argv) {
    if(argc != 2 || strcmp(argv[1], "-h") == 0)
        exitmsg("Usage: " << argv[0] << " (<command>|<path>)");

    auto file = open_man(argv[1]);

    ssize_t num;
    char buf[1024];
    while((num = file->read(buf, sizeof(buf))) > 0)
        cout.write_all(buf, static_cast<size_t>(num));
    return 0;
}
