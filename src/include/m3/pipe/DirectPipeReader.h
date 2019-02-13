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

#pragma once

#include <base/Common.h>

#include <m3/com/GateStream.h>
#include <m3/vfs/File.h>

namespace m3 {

class DirectPipe;

/**
 * Reads from a previously constructed pipe.
 */
class DirectPipeReader : public File {
    friend class DirectPipe;

public:
    struct State {
        explicit State(capsel_t caps);

        MemGate _mgate;
        RecvGate _rgate;
        size_t _pos;
        size_t _rem;
        size_t _pkglen;
        int _eof;
        GateIStream _is;
    };

    explicit DirectPipeReader(capsel_t caps, State *state);

public:
    /**
     * Sends EOF
     */
    ~DirectPipeReader();

    virtual Errors::Code stat(FileInfo &) const override {
        // not supported
        return Errors::NOT_SUP;
    }
    virtual ssize_t seek(size_t, int) override {
        // not supported
        return Errors::NOT_SUP;
    }

    virtual ssize_t read(void *buffer, size_t count) override {
        return read(buffer, count, true);
    }
    // returns -1 when in non blocking mode and there is no data to read
    ssize_t read(void *, size_t, bool blocking);
    virtual ssize_t write(const void *, size_t) override {
        // not supported
        return 0;
    }

    virtual Reference<File> clone() const override {
        return Reference<File>();
    }

    virtual char type() const override {
        return 'Q';
    }
    virtual Errors::Code delegate(VPE &vpe) override;
    virtual void serialize(Marshaller &m) override;
    static File *unserialize(Unmarshaller &um);

private:
    virtual void close() override;

    bool _noeof;
    capsel_t _caps;
    State *_state;
};

}
