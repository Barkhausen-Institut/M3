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

#include <base/Machine.h>

#include <m3/Exception.h>
#include <m3/tiles/OwnActivity.h>
#include <m3/vfs/File.h>
#include <m3/vfs/FileTable.h>

namespace m3 {

/**
 * The base-class for a file that reads/writes from/to a pipe. Can't be instantiated.
 */
class SerialFile : public File {
public:
    explicit SerialFile() noexcept : File(FILE_RW) {
    }

    virtual Errors::Code try_stat(FileInfo &info) const override {
        memset(&info, 0, sizeof(info));
        info.mode = M3FS_IFCHR | M3FS_MODE_READ | M3FS_MODE_WRITE;
        return Errors::NONE;
    }
    virtual size_t seek(size_t, int) override {
        throw Exception(Errors::NOT_SUP);
    }
    virtual void map(Reference<Pager> &, goff_t *, size_t, size_t, int, int) const override {
        throw Exception(Errors::NOT_SUP);
    }

    virtual ssize_t read(void *, size_t) override {
        // there is never anything to read
        return 0;
    }
    virtual ssize_t write(const void *buffer, size_t count) override {
        auto buf = reinterpret_cast<const char*>(buffer);
        while(count > 0) {
            ssize_t res = Machine::write(buf, count);
            if(res < 0)
                throw Exception(static_cast<Errors::Code>(-res));
            count -= static_cast<size_t>(res);
            buf += res;
        }
        return static_cast<ssize_t>(buf - reinterpret_cast<const char*>(buffer));
    }

    virtual FileRef<File> clone() const override {
        auto file = std::unique_ptr<File>(new SerialFile());
        return Activity::own().files()->alloc(std::move(file));
    }

    virtual char type() const noexcept override {
        return 'S';
    }
    virtual void delegate(ChildActivity &) override {
        // nothing to do
    }
    virtual void serialize(Marshaller &) override {
        // nothing to do
    }
    static SerialFile *unserialize(Unmarshaller &) {
        return new SerialFile();
    }

    virtual void remove() noexcept override {
    }
};

}
