/*
 * Copyright (C) 2015-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE // for setenv
#endif

#include <base/log/Lib.h>
#include <base/stream/Serial.h>
#include <base/Init.h>

#include <m3/com/Marshalling.h>
#include <m3/EnvVars.h>
#include <m3/vfs/File.h>
#include <m3/vfs/FileTable.h>
#include <m3/vfs/MountTable.h>
#include <m3/vfs/VFS.h>
#include <m3/tiles/Activity.h>

namespace m3 {

constexpr size_t MAX_PATH_LEN = 256;

// clean them up after the standard streams have been destructed
INIT_PRIO_VFS VFS::Cleanup VFS::_cleanup;

VFS::Cleanup::~Cleanup() {
    Activity::own().files()->remove_all();
    Activity::own().mounts()->remove_all();
}

std::unique_ptr<MountTable> &VFS::ms() {
    return Activity::own().mounts();
}

size_t VFS::abs_path(char *dst, size_t max, const char *src) {
    if(*src != '/') {
        const char *dir = cwd();
        size_t dir_len = strlen(dir);
        strncpy(dst, dir, dir_len);
        // add slash if it's not the root path
        if(dir_len != 1) {
            dst[dir_len] = '/';
            dir_len++;
            dst[dir_len] = '\0';
        }
        size_t res = dir_len + canon_path(dst + dir_len, max - dir_len, src);
        // we don't know in advance whether canon_path will add anything; if it did not and it's not
        // the root path, remove the ending slash
        if(res > 1 && dst[res - 1] == '/') {
            dst[res - 1] = '\0';
            res--;
        }
        return res;
    }

    return canon_path(dst, max, src);
}

size_t VFS::canon_path(char *dst, size_t max, const char *src) {
    size_t begin = 0;
    size_t count = 0;
    char *pathtemp = dst;

    const char *p = src;
    if(*p == '/') {
        *pathtemp++ = '/';
        *pathtemp = '\0';
        begin++;
        count++;
        while(*p == '/')
            p++;
    }

    while(*p) {
        const char *next_slash = strchr(p, '/');
        int pos = next_slash ? next_slash - p : static_cast<int>(strlen(p));

        // simply skip '.'
        if(pos == 1 && p[0] == '.')
            p += 2;
        // one layer back
        else if(pos == 2 && p[0] == '.' && p[1] == '.') {
            // to last slash
            while(count > begin && *pathtemp != '/') {
                pathtemp--;
                count--;
            }
            *pathtemp = '\0';
            p += 3;
        }
        else {
            if(max - count < (size_t)(pos + 2))
                return count;
            // append to path
            if(pathtemp != dst && pathtemp[-1] != '/') {
                *pathtemp++ = '/';
                count++;
            }
            strncpy(pathtemp, p, static_cast<size_t>(pos));
            pathtemp[pos] = '\0';
            pathtemp += pos;
            count += static_cast<size_t>(pos);
            p += pos + 1;
        }

        // one step too far?
        if(*(p - 1) == '\0')
            break;

        // skip multiple '/'
        while(*p == '/')
            p++;
    }

    if(pathtemp == dst)
        *pathtemp = '\0';

    return count;
}

const char *VFS::cwd() {
    const char *cwd = EnvVars::get("PWD");
    return cwd ? cwd : "/";
}

void VFS::set_cwd(const char *path) {
    if(path) {
        auto file = open(path, FILE_R);
        set_cwd(file->fd());
    }
    else
        EnvVars::remove("PWD");
}

void VFS::set_cwd(int fd) {
    auto file = Activity::own().files()->get(fd);

    FileInfo info;
    file->stat(info);
    if(!M3FS_ISDIR(info.mode))
        throw Exception(Errors::IS_NO_DIR);

    char buf[256];
    m3::String path = file->path();
    abs_path(buf, sizeof(buf), path.c_str());
    EnvVars::set("PWD", buf);
}

void VFS::mount(const char *path, const char *fs, const char *options) {
    if(ms()->indexof_mount(path) != MountTable::MAX_MOUNTS)
        throw Exception(Errors::EXISTS);

    auto id = ms()->alloc_id();
    FileSystem *fsobj;
    if(strcmp(fs, "m3fs") == 0)
        fsobj = new M3FS(id, options ? options : fs);
    else
        VTHROW(Errors::INV_ARGS, "Unknown filesystem '" << fs << "'");
    ms()->add(path, Reference<FileSystem>(fsobj));
}

void VFS::unmount(const char *path) {
    ms()->remove(path);
}

FileRef<GenericFile> VFS::open(const char *path, int flags) {
    try {
        char buffer[MAX_PATH_LEN];
        const char *fs_path = path;
        Reference<FileSystem> fs = ms()->resolve(&fs_path, buffer, sizeof(buffer));
        std::unique_ptr<GenericFile> file = fs->open(fs_path, flags);
        auto fileref = Activity::own().files()->alloc(std::move(file));
        LLOG(FS, "GenFile[" << fileref->fd() << "]::open(" << path << ", " << flags << ")");
        if(flags & FILE_APPEND)
            fileref->seek(0, M3FS_SEEK_END);
        return fileref;
    }
    catch(const Exception &e) {
        VTHROW(e.code(), "Unable to open '" << path << "' with flags=" << flags);
    }
}

void VFS::stat(const char *path, FileInfo &info) {
    Errors::Code res = try_stat(path, info);
    if(res != Errors::NONE)
        VTHROW(res, "stat '" << path << "' failed");
}

Errors::Code VFS::try_stat(const char *path, FileInfo &info) noexcept {
    char buffer[MAX_PATH_LEN];
    const char *fs_path = path;
    Reference<FileSystem> fs = ms()->try_resolve(&fs_path, buffer, sizeof(buffer));
    if(!fs)
        return Errors::NO_SUCH_FILE;
    return fs->try_stat(fs_path, info);
}

void VFS::mkdir(const char *path, mode_t mode) {
    Errors::Code res = try_mkdir(path, mode);
    if(res != Errors::NONE)
        VTHROW(res, "mkdir '" << path << "' failed");
}

Errors::Code VFS::try_mkdir(const char *path, mode_t mode) {
    char buffer[MAX_PATH_LEN];
    const char *fs_path = path;
    Reference<FileSystem> fs = ms()->try_resolve(&fs_path, buffer, sizeof(buffer));
    if(!fs)
        return Errors::NO_SUCH_FILE;
    return fs->try_mkdir(fs_path, mode);
}

void VFS::rmdir(const char *path) {
    Errors::Code res = try_rmdir(path);
    if(res != Errors::NONE)
        VTHROW(res, "rmdir '" << path << "' failed");
}

Errors::Code VFS::try_rmdir(const char *path) {
    char buffer[MAX_PATH_LEN];
    const char *fs_path = path;
    Reference<FileSystem> fs = ms()->try_resolve(&fs_path, buffer, sizeof(buffer));
    if(!fs)
        return Errors::NO_SUCH_FILE;
    return fs->try_rmdir(fs_path);
}

void VFS::link(const char *oldpath, const char *newpath) {
    Errors::Code res = try_link(oldpath, newpath);
    if(res != Errors::NONE)
        VTHROW(res, "link '" << oldpath << "' to '" << newpath << "' failed");
}

Errors::Code VFS::try_link(const char *oldpath, const char *newpath) {
    char buffer1[MAX_PATH_LEN];
    char buffer2[MAX_PATH_LEN];
    const char *fs_path1 = oldpath;
    const char *fs_path2 = newpath;
    Reference<FileSystem> fs1 = ms()->try_resolve(&fs_path1, buffer1, sizeof(buffer1));
    Reference<FileSystem> fs2 = ms()->try_resolve(&fs_path2, buffer2, sizeof(buffer2));
    if(!fs1 || !fs2)
        return Errors::NO_SUCH_FILE;
    if(fs1.get() != fs2.get())
        return Errors::XFS_LINK;
    return fs1->try_link(fs_path1, fs_path2);
}

void VFS::unlink(const char *path) {
    Errors::Code res = try_unlink(path);
    if(res != Errors::NONE)
        VTHROW(res, "unlink '" << path << "' failed");
}

Errors::Code VFS::try_unlink(const char *path) {
    char buffer[MAX_PATH_LEN];
    const char *fs_path = path;
    Reference<FileSystem> fs = ms()->try_resolve(&fs_path, buffer, sizeof(buffer));
    if(!fs)
        return Errors::NO_SUCH_FILE;
    return fs->try_unlink(fs_path);
}

void VFS::rename(const char *oldpath, const char *newpath) {
    Errors::Code res = try_rename(oldpath, newpath);
    if(res != Errors::NONE)
        VTHROW(res, "rename '" << oldpath << "' to '" << newpath << "' failed");
}

Errors::Code VFS::try_rename(const char *oldpath, const char *newpath) {
    char buffer1[MAX_PATH_LEN];
    char buffer2[MAX_PATH_LEN];
    const char *fs_path1 = oldpath;
    const char *fs_path2 = newpath;
    Reference<FileSystem> fs1 = ms()->try_resolve(&fs_path1, buffer1, sizeof(buffer1));
    Reference<FileSystem> fs2 = ms()->try_resolve(&fs_path2, buffer2, sizeof(buffer2));
    if(!fs1 || !fs2)
        return Errors::NO_SUCH_FILE;
    if(fs1.get() != fs2.get())
        return Errors::XFS_LINK;
    return fs1->try_rename(fs_path1, fs_path2);
}

void VFS::print(OStream &os) noexcept {
    Activity::own().mounts()->print(os);
}

}
