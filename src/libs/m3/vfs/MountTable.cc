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

#include <m3/com/Marshalling.h>
#include <m3/com/GateStream.h>
#include <m3/session/M3FS.h>
#include <m3/vfs/MountTable.h>
#include <m3/vfs/VFS.h>
#include <m3/Exception.h>

namespace m3 {

static size_t charcount(const char *str, char c) {
    size_t cnt = 0;
    while(*str) {
        if(*str == c)
            cnt++;
        str++;
    }
    // if the path does not end with a slash, we have essentially one '/' more
    if(str[-1] != '/')
        cnt++;
    return cnt;
}

// TODO this is a very simple solution that expects "perfect" paths, i.e. with no "." or ".." and
// no duplicate slashes (at least not just one path):
static size_t is_in_mount(const String &mount, const char *in) {
    const char *p1 = mount.c_str();
    const char *p2 = in;
    while(*p2 && *p1 == *p2) {
        p1++;
        p2++;
    }
    while(*p1 == '/')
        p1++;
    if(*p1)
        return 0;
    while(*p2 == '/')
        p2++;
    return static_cast<size_t>(p2 - in);
}

MountTable::~MountTable() {
    for(size_t i = 0; i < MAX_MOUNTS; ++i)
        delete _mounts[i];
}

void MountTable::add(const char *path, Reference<FileSystem> fs) {
    if(_count == MAX_MOUNTS)
        throw MessageException("No free slot in mount table", Errors::NO_SPACE);

    size_t compcount = charcount(path, '/');
    size_t i = 0;
    for(; i < _count; ++i) {
        // mounts are always tightly packed
        assert(_mounts[i]);

        if(strcmp(_mounts[i]->path().c_str(), path) == 0)
            VTHROW(Errors::EXISTS, "Mountpoint " << path << " already exists");

        // sort them by the number of slashes
        size_t cnt = charcount(_mounts[i]->path().c_str(), '/');
        if(compcount > cnt)
            break;
    }
    assert(i < MAX_MOUNTS);

    // move following items forward
    if(_count > 0) {
        for(size_t j = _count; j > i; --j)
            _mounts[j] = _mounts[j - 1];
    }
    _mounts[i] = new MountPoint(path, fs);
    // ensure that we don't reuse ids, even if this filesystem was added after unserialization
    _next_id = Math::max(fs->id() + 1, _next_id);
    _count++;
}

Reference<FileSystem> MountTable::resolve(const char **path, char *buffer, size_t bufsize) {
    auto res = try_resolve(path, buffer, bufsize);
    if(res)
        return res;
    VTHROW(Errors::NO_SUCH_FILE, "Unable to resolve path '" << *path << "'");
}

Reference<FileSystem> MountTable::try_resolve(const char **path, char *buffer, size_t bufsize) noexcept {
    if(**path != '/') {
        OStringStream os(buffer, bufsize);
        const char *cwd = VFS::cwd();
        os << cwd;
        if(strcmp(cwd, "/") != 0)
            os << "/";
        os << *path;
        *path = buffer;
    }

    for(size_t i = 0; i < _count; ++i) {
        size_t pos = is_in_mount(_mounts[i]->path(), *path);
        if(pos != 0) {
            *path = *path + pos;
            return _mounts[i]->fs();
        }
    }
    return Reference<FileSystem>();
}

Reference<FileSystem> MountTable::get_by_id(size_t id) noexcept {
    for(size_t i = 0; i < _count; ++i) {
        if(_mounts[i]->fs()->id() == id)
            return _mounts[i]->fs();
    }
    return Reference<FileSystem>();
}

const char *MountTable::path_of_id(size_t id) noexcept {
    for(size_t i = 0; i < _count; ++i) {
        if(_mounts[i]->fs()->id() == id)
            return _mounts[i]->path().c_str();
    }
    return nullptr;
}

size_t MountTable::indexof_mount(const char *path) {
    for(size_t i = 0; i < _count; ++i) {
        if(strcmp(_mounts[i]->path().c_str(), path) == 0)
            return i;
    }
    return MAX_MOUNTS;
}

void MountTable::remove(const char *path) {
    size_t idx = indexof_mount(path);
    if(idx != MAX_MOUNTS)
        do_remove(idx);
}

void MountTable::remove_all() noexcept {
    while(_count > 0)
        do_remove(0);
}

void MountTable::do_remove(size_t i) {
    assert(_mounts[i] != nullptr);
    assert(_count > 0);
    delete _mounts[i];
    // move following items backwards
    for(; i < _count - 1; ++i)
        _mounts[i] = _mounts[i + 1];
    _count--;
    _mounts[_count] = nullptr;
}

size_t MountTable::serialize(ChildActivity &act, void *buffer, size_t size) const {
    Marshaller m(static_cast<unsigned char*>(buffer), size);

    m << act._mounts.size();
    for(auto mapping = act._mounts.begin(); mapping != act._mounts.end(); ++mapping) {
        auto mount = Activity::own().mounts()->get(mapping->second.c_str());
        auto type = mount->type();
        m << mapping->first << type;
        switch(type) {
            case 'M':
                mount->serialize(m);
                break;
        }
    }
    return m.total();
}

void MountTable::delegate(ChildActivity &act) const {
    for(auto mapping = act._mounts.begin(); mapping != act._mounts.end(); ++mapping) {
        auto mount = Activity::own().mounts()->get(mapping->second.c_str());
        char type = mount->type();
        switch(type) {
            case 'M':
                mount->delegate(act);
                break;
        }
    }
}

MountTable *MountTable::unserialize(const void *buffer, size_t size) {
    MountTable *ms = new MountTable();
    Unmarshaller um(static_cast<const unsigned char*>(buffer), size);
    size_t count;
    um >> count;
    while(count-- > 0) {
        char type;
        String path;
        um >> path >> type;
        switch(type) {
            case 'M':
                ms->add(path.c_str(), Reference<FileSystem>(M3FS::unserialize(um)));
                break;
        }
    }
    return ms;
}

void MountTable::print(OStream &os) const noexcept {
    os << "Mounts:\n";
    for(size_t i = 0; i < _count; ++i)
        os << "  " << _mounts[i]->path() << ": " << _mounts[i]->fs()->type() << "\n";
}

}
