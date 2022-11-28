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

#pragma once

#include <base/Errors.h>
#include <base/util/Reference.h>

#include <m3/Exception.h>
#include <m3/vfs/GenericFile.h>

#include <fs/internal.h>

namespace m3 {

class File;
class Marshaller;

/**
 * The base-class of all filesystems
 */
class FileSystem : public RefCounted {
public:
    enum Operation {
        FSTAT = GenericFile::STAT,
        SEEK = GenericFile::SEEK,
        NEXT_IN = GenericFile::NEXT_IN,
        NEXT_OUT = GenericFile::NEXT_OUT,
        COMMIT = GenericFile::COMMIT,
        TRUNCATE = GenericFile::TRUNCATE,
        SYNC = GenericFile::SYNC,
        CLOSE = GenericFile::CLOSE,
        CLONE = GenericFile::CLONE,
        GET_HASH = GenericFile::GET_HASH,
        GET_TMODE = GenericFile::GET_TMODE,
        SET_TMODE = GenericFile::SET_TMODE,
        SET_DEST = GenericFile::SET_DEST,
        ENABLE_NOTIFY = GenericFile::ENABLE_NOTIFY,
        REQ_NOTIFY = GenericFile::REQ_NOTIFY,
        STAT,
        MKDIR,
        RMDIR,
        LINK,
        UNLINK,
        RENAME,
        OPEN,
        GET_SGATE,
        GET_MEM,
        DEL_EP,
        OPEN_PRIV,
    };

    explicit FileSystem(size_t id) noexcept : RefCounted(), _id(id) {
    }
    virtual ~FileSystem() {
    }

    /**
     * @return the id of this file system (within all local mounts)
     */
    size_t id() const noexcept {
        return _id;
    }

    /**
     * @return for serialization: the type of fs
     */
    virtual char type() const noexcept = 0;

    /**
     * Creates a File-instance from given path with given permissions.
     *
     * @param path the filepath
     * @param perms the permissions (FILE_*)
     * @return the File-instance
     */
    virtual std::unique_ptr<GenericFile> open(const char *path, int perms) = 0;

    /**
     * Closes the given file.
     *
     * @param file_id the server-side file id
     */
    virtual void close(size_t file_id) = 0;

    /**
     * Retrieves the file information for the given path.
     *
     * @param path the path
     * @param info where to write to
     */
    void stat(const char *path, FileInfo &info) {
        Errors::Code res = try_stat(path, info);
        if(res != Errors::SUCCESS)
            throw Exception(res);
    }

    /**
     * Tries to retrieve the file information for the given path. That is, on error it does not
     * throw an exception, but the error code is returned.
     *
     * @param path the path
     * @param info where to write to
     * @return the error code on failure
     */
    virtual Errors::Code try_stat(const char *path, FileInfo &info) noexcept = 0;

    /**
     * Creates the given directory.
     *
     * @param path the directory path
     * @param mode the permissions to assign
     */
    void mkdir(const char *path, mode_t mode) {
        Errors::Code res = try_mkdir(path, mode);
        if(res != Errors::SUCCESS)
            throw Exception(res);
    }

    /**
     * Tries to create the given directory. That is, on error it does not throw an exception, but
     * the error code is returned.
     *
     * @param path the directory path
     * @param mode the permissions to assign
     * @return the error code on failure
     */
    virtual Errors::Code try_mkdir(const char *path, mode_t mode) = 0;

    /**
     * Removes the given directory. It needs to be empty.
     *
     * @param path the directory path
     */
    void rmdir(const char *path) {
        Errors::Code res = try_rmdir(path);
        if(res != Errors::SUCCESS)
            throw Exception(res);
    }

    /**
     * Tries to remove the given directory. That is, on error it does not throw an exception, but
     * the error code is returned. It needs to be empty.
     *
     * @param path the directory path
     * @return the error code on failure
     */
    virtual Errors::Code try_rmdir(const char *path) = 0;

    /**
     * Creates a link at <newpath> to <oldpath>.
     *
     * @param oldpath the existing path
     * @param newpath the link to create
     */
    void link(const char *oldpath, const char *newpath) {
        Errors::Code res = try_link(oldpath, newpath);
        if(res != Errors::SUCCESS)
            throw Exception(res);
    }

    /**
     * Tries to create a link at <newpath> to <oldpath>. That is, on error it does not throw an
     * exception, but the error code is returned.
     *
     * @param oldpath the existing path
     * @param newpath the link to create
     * @return the error code on failure
     */
    virtual Errors::Code try_link(const char *oldpath, const char *newpath) = 0;

    /**
     * Removes the given file.
     *
     * @param path the path
     */
    void unlink(const char *path) {
        Errors::Code res = try_unlink(path);
        if(res != Errors::SUCCESS)
            throw Exception(res);
    }

    /**
     * Tries to remove the given file. That is, on error it does not throw an exception, but the
     * error code is returned.
     *
     * @param path the path
     * @return the error code on failure
     */
    virtual Errors::Code try_unlink(const char *path) = 0;

    /**
     * Renames <newpath> to <oldpath>.
     *
     * @param oldpath the existing path
     * @param newpath the new path
     */
    void rename(const char *oldpath, const char *newpath) {
        Errors::Code res = try_rename(oldpath, newpath);
        if(res != Errors::SUCCESS)
            throw Exception(res);
    }

    /**
     * Tries to rename <newpath> to <oldpath>. That is, on error it does not throw an exception, but
     * the error code is returned.
     *
     * @param oldpath the existing path
     * @param newpath the new path
     * @return the error code on failure
     */
    virtual Errors::Code try_rename(const char *oldpath, const char *newpath) = 0;

    /**
     * Delegates all this filesystem to the given activity.
     *
     * @param act the activity
     */
    virtual void delegate(ChildActivity &act) = 0;

    /**
     * Serializes this object to the given marshaller.
     *
     * @param m the marshaller
     */
    virtual void serialize(Marshaller &m) = 0;

private:
    size_t _id;
};

}
