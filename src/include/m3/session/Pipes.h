/*
 * Copyright (C) 2016-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#pragma once

#include <m3/session/ClientSession.h>
#include <m3/com/GateStream.h>
#include <m3/com/SendGate.h>
#include <m3/vfs/GenericFile.h>
#include <m3/vfs/FileTable.h>

namespace m3 {

class Pipes : public ClientSession {
    enum {
        OPEN_PIPE     = GenericFile::REQ_NOTIFY + 1,
        OPEN_CHAN,
        SET_MEM,
        CLOSE_PIPE,
    };

public:
    class Pipe : public ClientSession {
    public:
        explicit Pipe(capsel_t sel, MemGate &memory)
            : ClientSession(sel),
              _sgate(SendGate::bind(sel + 1)) {
            KIF::ExchangeArgs args;
            ExchangeOStream os(args);
            os << SET_MEM;
            args.bytes = os.total();
            delegate(KIF::CapRngDesc(KIF::CapRngDesc::OBJ, memory.sel(), 1), &args);
        }
        Pipe(Pipe &&p) noexcept
            : ClientSession(std::move(p)), _sgate(std::move(p._sgate)) {
        }
        virtual ~Pipe() {
            send_receive_vmsg(_sgate, CLOSE_PIPE);
        }

        FileRef<GenericFile> create_channel(bool read, int flags = 0) {
            KIF::ExchangeArgs args;
            ExchangeOStream os(args);
            os << OPEN_CHAN << read;
            args.bytes = os.total();
            KIF::CapRngDesc desc = obtain(2, &args);
            flags |= FILE_NEWSESS | (read ? FILE_R : FILE_W);
            auto file = std::unique_ptr<GenericFile>(
                new GenericFile(flags, desc.start(), static_cast<size_t>(-1)));
            return Activity::own().files()->alloc(std::move(file));
        }

    private:
        SendGate _sgate;
    };

    explicit Pipes(const String &service)
        : ClientSession(service) {
    }

    Pipe create_pipe(MemGate &memory, size_t memsize) {
        KIF::ExchangeArgs args;
        ExchangeOStream os(args);
        os << OPEN_PIPE << memsize;
        args.bytes = os.total();
        KIF::CapRngDesc desc = obtain(2, &args);
        return Pipe(desc.start(), memory);
    }
};

}
