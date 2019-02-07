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

#include <base/CmdArgs.h>
#include <base/Common.h>
#include <base/Errors.h>
#include <base/stream/IStringStream.h>

#include <m3/server/RequestHandler.h>
#include <m3/server/Server.h>
#include <m3/session/Disk.h>
#include <m3/session/M3FS.h>
#include <m3/session/ServerSession.h>
#include <m3/stream/Standard.h>

#include <limits>
#include <stdlib.h>

#include "backend/DiskBackend.h"
#include "backend/MemBackend.h"
#include "data/Dirs.h"
#include "data/INodes.h"
#include "sess/FileSession.h"
#include "sess/MetaSession.h"
#include "FSHandle.h"

// TODO remove workloop; do it like in rust

// TODO rust-unittests tpipe child_to_parent is broken with MMU=1

using namespace m3;

class M3FSRequestHandler;

using base_class = RequestHandler<M3FSRequestHandler, M3FS::Operation, M3FS::COUNT, M3FSSession>;

static Server<M3FSRequestHandler> *srv;

class M3FSRequestHandler : public base_class {
public:
    explicit M3FSRequestHandler(Backend *backend, size_t extend, bool clear,
                                bool revoke_first, size_t max_load)
        : base_class(),
          _rgate(RecvGate::create(nextlog2<32 * M3FSSession::MSG_SIZE>::val,
                                  nextlog2<M3FSSession::MSG_SIZE>::val)),
          _handle(backend, extend, clear, revoke_first, max_load) {
        add_operation(M3FS::OPEN_PRIV, &M3FSRequestHandler::open_private_file);
        add_operation(M3FS::CLOSE_PRIV, &M3FSRequestHandler::close_private_file);
        add_operation(M3FS::NEXT_IN, &M3FSRequestHandler::next_in);
        add_operation(M3FS::NEXT_OUT, &M3FSRequestHandler::next_out);
        add_operation(M3FS::COMMIT, &M3FSRequestHandler::commit);
        add_operation(M3FS::FSTAT, &M3FSRequestHandler::fstat);
        add_operation(M3FS::SEEK, &M3FSRequestHandler::seek);
        add_operation(M3FS::STAT, &M3FSRequestHandler::stat);
        add_operation(M3FS::MKDIR, &M3FSRequestHandler::mkdir);
        add_operation(M3FS::RMDIR, &M3FSRequestHandler::rmdir);
        add_operation(M3FS::LINK, &M3FSRequestHandler::link);
        add_operation(M3FS::UNLINK, &M3FSRequestHandler::unlink);

        using std::placeholders::_1;
        _rgate.start(std::bind(&M3FSRequestHandler::handle_message, this, _1));
    }

    virtual Errors::Code open(M3FSSession **sess, capsel_t srv_sel, word_t) override {
        *sess = new M3FSMetaSession(_handle, srv_sel, _rgate);
        return Errors::NONE;
    }

    virtual Errors::Code obtain(M3FSSession *sess, KIF::Service::ExchangeData &data) override {
        if(sess->type() == M3FSSession::META) {
            auto meta = static_cast<M3FSMetaSession *>(sess);
            if(data.args.count == 0)
                return meta->get_sgate(data);
            return meta->open_file(srv->sel(), data);
        }
        else {
            auto file = static_cast<M3FSFileSession *>(sess);
            if(data.args.count == 0)
                return file->clone(srv->sel(), data);
            return file->get_mem(data);
        }
    }

    virtual Errors::Code delegate(M3FSSession *sess, KIF::Service::ExchangeData &data) override {
        if(data.args.count != 0)
            return Errors::NOT_SUP;

        if(sess->type() == M3FSSession::META) {
            if(data.caps == 0)
                return Errors::INV_ARGS;
            capsel_t sels = VPE::self().alloc_sels(data.caps);
            static_cast<M3FSMetaSession *>(sess)->set_eps(sels, data.caps);
            data.caps = KIF::CapRngDesc(KIF::CapRngDesc::OBJ, sels, data.caps).value();
            return Errors::NONE;
        }
        else {
            if(data.caps != 1)
                return Errors::NOT_SUP;
            capsel_t sel = VPE::self().alloc_sel();
            static_cast<M3FSFileSession *>(sess)->set_ep(sel);
            data.caps = KIF::CapRngDesc(KIF::CapRngDesc::OBJ, sel, data.caps).value();
            return Errors::NONE;
        }
    }

    virtual Errors::Code close(M3FSSession *sess) override {
        delete sess;
        _rgate.drop_msgs_with(reinterpret_cast<label_t>(sess));
        return Errors::NONE;
    }

    virtual void shutdown() override {
        _rgate.stop();
        _handle.flush_buffer();
        _handle.shutdown();
    }

    void open_private_file(GateIStream &is) {
        M3FSSession *sess = is.label<M3FSSession *>();
        sess->open_private_file(is);
    }

    void close_private_file(GateIStream &is) {
        M3FSSession *sess = is.label<M3FSSession *>();
        sess->close_private_file(is);
    }

    void next_in(GateIStream &is) {
        M3FSSession *sess = is.label<M3FSSession *>();
        sess->next_in(is);
    }

    void next_out(GateIStream &is) {
        M3FSSession *sess = is.label<M3FSSession *>();
        sess->next_out(is);
    }

    void commit(GateIStream &is) {
        M3FSSession *sess = is.label<M3FSSession *>();
        sess->commit(is);
    }

    void seek(GateIStream &is) {
        M3FSSession *sess = is.label<M3FSSession *>();
        sess->seek(is);
    }

    void fstat(GateIStream &is) {
        M3FSSession *sess = is.label<M3FSSession *>();
        sess->fstat(is);
    }

    void stat(GateIStream &is) {
        M3FSSession *sess = is.label<M3FSSession *>();
        sess->stat(is);
    }

    void mkdir(GateIStream &is) {
        M3FSSession *sess = is.label<M3FSSession *>();
        sess->mkdir(is);
    }

    void rmdir(GateIStream &is) {
        M3FSSession *sess = is.label<M3FSSession *>();
        sess->rmdir(is);
    }

    void link(GateIStream &is) {
        M3FSSession *sess = is.label<M3FSSession *>();
        sess->link(is);
    }

    void unlink(GateIStream &is) {
        M3FSSession *sess = is.label<M3FSSession *>();
        sess->unlink(is);
    }

private:
    RecvGate _rgate;
    //MemGate _mem;
    FSHandle _handle;
};

NORETURN static void usage(const char *name) {
    cerr << "Usage: " << name
         << " [-n <name>] [-s <sel>] [-e <blocks>] [-c] [-r] [-b <blocks>]\n"
         << " [-o <offset>] (disk <dev>|mem <fssize>)\n";
    cerr << "  -n: the name of the service (m3fs by default)\n";
    cerr << "  -s: don't create service, use selectors <sel>..<sel+1>\n";
    cerr << "  -e: the number of blocks to extend files when appending\n";
    cerr << "  -c: clear allocated blocks\n";
    cerr << "  -r: revoke first, reply afterwards\n";
    cerr << "  -b: the maximum number of blocks loaded from the disk\n";
    cerr << "  -o: the file system offset in DRAM\n";
    exit(1);
}

int main(int argc, char *argv[]) {
    const char *name  = "m3fs";
    size_t extend     = 128;
    size_t max_load   = 128;
    bool clear        = false;
    bool revoke_first = false;
    capsel_t sels     = ObjCap::INVALID;
    epid_t ep         = EP_COUNT;
    goff_t fs_offset  = FS_IMG_OFFSET;

    int opt;
    while((opt = CmdArgs::get(argc, argv, "n:s:e:crb:o:")) != -1) {
        switch(opt) {
            case 'n': name = CmdArgs::arg; break;
            case 's': {
                String input(CmdArgs::arg);
                IStringStream is(input);
                is >> sels >> ep;
                break;
            }
            case 'e': extend = IStringStream::read_from<size_t>(CmdArgs::arg); break;
            case 'c': clear = true; break;
            case 'r': revoke_first = true; break;
            case 'b': max_load = IStringStream::read_from<size_t>(CmdArgs::arg); break;
            case 'o': fs_offset = IStringStream::read_from<goff_t>(CmdArgs::arg); break;
            default: usage(argv[0]);
        }
    }
    if(CmdArgs::ind + 1 >= argc)
        usage(argv[0]);

    // create backend
    Backend *backend;
    const char *backend_type = argv[CmdArgs::ind];
    if(strcmp(backend_type, "disk") == 0) {
        size_t dev = IStringStream::read_from<size_t>(argv[CmdArgs::ind + 1]);
        backend = new DiskBackend(dev);
    }
    else if(strcmp(backend_type, "mem") == 0) {
        size_t fs_size = IStringStream::read_from<size_t>(argv[CmdArgs::ind + 1]);
        backend = new MemBackend(fs_offset, fs_size);
    }
    else
        usage(argv[0]);

    auto hdl    = new M3FSRequestHandler(backend, extend, clear, revoke_first, max_load);
    if(sels != ObjCap::INVALID)
        srv = new Server<M3FSRequestHandler>(sels, ep, hdl);
    else
        srv = new Server<M3FSRequestHandler>(name, hdl);

    env()->workloop()->multithreaded(16);
    env()->workloop()->run();

    delete backend;
    delete srv;
    return 0;
}
