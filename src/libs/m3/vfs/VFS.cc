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

#include <base/log/Lib.h>
#include <base/stream/Serial.h>
#include <base/Init.h>

#include <m3/com/Marshalling.h>
#include <m3/vfs/File.h>
#include <m3/vfs/FileTable.h>
#include <m3/vfs/MountTable.h>
#include <m3/vfs/VFS.h>
#include <m3/VPE.h>

namespace m3 {

// clean them up after the standard streams have been destructed
INIT_PRIO_VFS VFS::Cleanup VFS::_cleanup;

VFS::Cleanup::~Cleanup() {
    VPE::self().fds()->remove_all();
    VPE::self().mounts()->remove_all();
}

MountTable *VFS::ms() {
    return VPE::self().mounts();
}

Errors::Code VFS::mount(const char *path, const char *fs, const char *options) {
    FileSystem *fsobj;
    if(strcmp(fs, "m3fs") == 0)
        fsobj = new M3FS(options ? options : fs);
    else
        return Errors::INV_ARGS;
    return ms()->add(path, fsobj);
}

void VFS::unmount(const char *path) {
    ms()->remove(path);
}

Errors::Code VFS::delegate_eps(const char *path, capsel_t first, uint count) {
    size_t pos;
    Reference<FileSystem> fs = ms()->resolve(path, &pos);
    if(!fs.valid())
        return Errors::last = Errors::NO_SUCH_FILE;
    return fs->delegate_eps(first, count);
}

fd_t VFS::open(const char *path, int perms) {
    size_t pos;
    Reference<FileSystem> fs = ms()->resolve(path, &pos);
    if(!fs.valid()) {
        Errors::last = Errors::NO_SUCH_FILE;
        return FileTable::INVALID;
    }
    Reference<File> file = fs->open(path + pos, perms);
    if(file.valid()) {
        fd_t fd = VPE::self().fds()->alloc(file);
        if(fd == FileTable::INVALID)
            Errors::last = Errors::NO_SPACE;
        LLOG(FS, "GenFile[" << fd << "]::open(" << path << ", " << perms << ")");
        if(perms & FILE_APPEND)
            file->seek(0, M3FS_SEEK_END);
        return fd;
    }
    return FileTable::INVALID;
}

void VFS::close(fd_t fd) {
    VPE::self().fds()->remove(fd);
}

Errors::Code VFS::stat(const char *path, FileInfo &info) {
    size_t pos;
    Reference<FileSystem> fs = ms()->resolve(path, &pos);
    if(!fs.valid())
        return Errors::last = Errors::NO_SUCH_FILE;
    return fs->stat(path + pos, info);
}

Errors::Code VFS::mkdir(const char *path, mode_t mode) {
    size_t pos;
    Reference<FileSystem> fs = ms()->resolve(path, &pos);
    if(!fs.valid())
        return Errors::last = Errors::NO_SUCH_FILE;
    return fs->mkdir(path + pos, mode);
}

Errors::Code VFS::rmdir(const char *path) {
    size_t pos;
    Reference<FileSystem> fs = ms()->resolve(path, &pos);
    if(!fs.valid())
        return Errors::last = Errors::NO_SUCH_FILE;
    return fs->rmdir(path + pos);
}

Errors::Code VFS::link(const char *oldpath, const char *newpath) {
    size_t pos1, pos2;
    Reference<FileSystem> fs1 = ms()->resolve(oldpath, &pos1);
    if(!fs1.valid())
        return Errors::last = Errors::NO_SUCH_FILE;
    Reference<FileSystem> fs2 = ms()->resolve(newpath, &pos2);
    if(!fs2.valid())
        return Errors::last = Errors::NO_SUCH_FILE;
    if(fs1.get() != fs2.get())
        return Errors::last = Errors::XFS_LINK;
    return fs1->link(oldpath + pos1, newpath + pos2);
}

Errors::Code VFS::unlink(const char *path) {
    size_t pos;
    Reference<FileSystem> fs = ms()->resolve(path, &pos);
    if(!fs.valid())
        return Errors::last = Errors::NO_SUCH_FILE;
    return fs->unlink(path + pos);
}

void VFS::print(OStream &os) {
    VPE::self().mounts()->print(os);
}

}
