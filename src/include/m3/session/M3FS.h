/*
 * Copyright (C) 2015, Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#pragma once

#include <base/util/Reference.h>

#include <m3/session/Session.h>
#include <m3/com/RecvGate.h>
#include <m3/com/SendGate.h>
#include <m3/vfs/FileSystem.h>

#include <fs/internal.h>

namespace m3 {

class M3FS : public Session, public FileSystem {
public:
    enum Operation {
        OPEN,
        STAT,
        FSTAT,
        SEEK,
        MKDIR,
        RMDIR,
        LINK,
        UNLINK,
        COMMIT,
        CLOSE,
        COUNT
    };

    enum Flags {
        BYTE_OFFSET = 1,
    };

    explicit M3FS(const String &service)
        : Session(service), FileSystem(), _gate(SendGate::bind(obtain(1).start())) {
    }
    explicit M3FS(capsel_t session, capsel_t gate)
        : Session(session), FileSystem(), _gate(SendGate::bind(gate)) {
    }

    const SendGate &gate() const {
        return _gate;
    }
    virtual char type() const override {
        return 'M';
    }

    virtual File *open(const char *path, int perms) override;
    virtual Errors::Code stat(const char *path, FileInfo &info) override;
    int fstat(int fd, FileInfo &info);
    int seek(int fd, size_t off, int whence, size_t &global, size_t &extoff, size_t &pos);
    virtual Errors::Code mkdir(const char *path, mode_t mode) override;
    virtual Errors::Code rmdir(const char *path) override;
    virtual Errors::Code link(const char *oldpath, const char *newpath) override;
    virtual Errors::Code unlink(const char *path) override;
    Errors::Code commit(int fd, size_t extent, size_t off);
    Errors::Code close(int fd, size_t extent, size_t off);

    template<size_t N>
    bool get_locs(int fd, size_t offset, size_t count, size_t blocks, KIF::CapRngDesc &crd, LocList<N> &locs) {
        return get_locs(*this, fd, &offset, count, blocks, crd, locs, 0);
    }

    // TODO wrong place. we should have a DataSpace session or something
    template<size_t N>
    static bool get_locs(Session &sess, int fd, size_t *offset, size_t count, size_t blocks,
            KIF::CapRngDesc &crd, LocList<N> &locs, uint flags) {
        xfer_t args[5];
        args[0] = static_cast<xfer_t>(fd);
        args[1] = *offset;
        args[2] = count;
        args[3] = blocks;
        args[4] = flags;
        bool extended = false;
        size_t argcount = ARRAY_SIZE(args);
        crd = sess.obtain(count, &argcount, args);
        if(Errors::last == Errors::NONE) {
            extended = args[0];
            *offset = args[1];
            for(size_t i = 2; i < argcount; ++i)
                locs.append(args[i]);
        }
        return extended;
    }

private:
    SendGate _gate;
};

}
