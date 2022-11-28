/*
 * Copyright (C) 2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <base/Common.h>

#include <m3/Exception.h>
#include <m3/com/MemGate.h>
#include <m3/com/SendGate.h>
#include <m3/session/ClientSession.h>
#include <m3/tiles/ChildActivity.h>
#include <m3/tiles/OwnActivity.h>
#include <m3/vfs/File.h>

namespace m3 {

class M3FS;

class GenericFile : public File {
    friend class FileTable;

public:
    enum Operation {
        STAT,
        SEEK,
        NEXT_IN,
        NEXT_OUT,
        COMMIT,
        TRUNCATE,
        SYNC,
        CLOSE,
        CLONE,
        GET_HASH,
        GET_PATH,
        GET_TMODE,
        SET_TMODE,
        SET_DEST,
        ENABLE_NOTIFY,
        REQ_NOTIFY,
    };

    explicit GenericFile(int flags, capsel_t caps, size_t fs_id, size_t id = 0,
                         epid_t mep = TCU::INVALID_EP, SendGate *sg = nullptr);
    virtual ~GenericFile();

    /**
     * @return true if there is still data to read or write without contacting the server
     */
    bool has_data() const noexcept {
        return _pos < _len;
    }

    virtual Errors::Code try_stat(FileInfo &info) const override;

    virtual size_t seek(size_t offset, int whence) override;

    virtual Option<size_t> read(void *buffer, size_t count) override;
    virtual Option<size_t> write(const void *buffer, size_t count) override;

    virtual void truncate(size_t length) override;

    virtual std::string path() override;

    virtual void flush() override {
        if(_writing)
            commit();
    }

    virtual void sync() override;

    virtual void map(Reference<Pager> &pager, goff_t *virt, size_t fileoff, size_t len, int prot,
                     int flags) const override;

    virtual Errors::Code try_get_tmode(File::TMode *mode) noexcept override;
    virtual void set_tmode(TMode mode) override;

    virtual bool fetch_signal() override;

    virtual char type() const noexcept override {
        return 'F';
    }

    void connect(EP &sep, EP &mep) const {
        _sg->activate_on(sep);
        do_delegate_ep(mep);
    }

    virtual FileRef<File> clone() const override;

    virtual void delegate(ChildActivity &act) override {
        if(!have_sess())
            throw Exception(Errors::NOT_SUP);
        KIF::CapRngDesc crd(KIF::CapRngDesc::OBJ, _sess.sel(), 2);
        do_clone(act, crd);
    }

    virtual void serialize(Marshaller &m) override {
        m << flags() << _sess.sel() << _fs_id;
    }

    static File *unserialize(Unmarshaller &um) {
        int fl;
        capsel_t caps;
        size_t fs_id;
        um >> fl >> caps >> fs_id;
        return new GenericFile(fl, caps, fs_id);
    }

private:
    virtual void remove() noexcept override;
    virtual bool check_events(uint events) override;

    bool have_sess() const noexcept {
        return (flags() & FILE_NEWSESS);
    }
    void do_clone(Activity &act, KIF::CapRngDesc &crd) const;
    void do_delegate_ep(const EP &ep) const;
    void commit();
    void delegate_ep();
    virtual void enable_notifications() override;
    void request_notification(uint events);
    bool receive_notify(uint event, bool fetch);

    size_t _fs_id;
    size_t _id;
    mutable ClientSession _sess;
    mutable SendGate *_sg;
    std::unique_ptr<RecvGate> _notify_rgate;
    std::unique_ptr<SendGate> _notify_sgate;
    uint8_t _notify_received;
    uint8_t _notify_requested;
    MemGate _mg;
    size_t _goff;
    size_t _off;
    size_t _pos;
    size_t _len;
    bool _writing;
};

}
