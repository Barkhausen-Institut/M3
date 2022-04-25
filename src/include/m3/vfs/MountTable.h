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

#include <base/Common.h>
#include <base/util/Reference.h>
#include <base/util/String.h>
#include <base/Errors.h>

#include <m3/vfs/FileSystem.h>

namespace m3 {

class Activity;

/**
 * Contains a list of mount points and offers operations to manage them.
 *
 * The mount table itself does not create or delete mount points. Instead, it only works with
 * pointers. The creation and deletion is done in VFS. The rational is, that VFS is used to
 * manipulate the mounts of the own activity, while MountTable is used to manipulate the mounts of
 * created activities. Thus, one can simply add a mointpoint from Activity::own() to a different activity by
 * passing a pointer around. If the mount table of a child activity is completely setup, it is serialized
 * and transferred to the child activity.
 */
class MountTable {
    class MountPoint {
    public:
        explicit MountPoint(const char *path, Reference<FileSystem> fs) noexcept
            : _path(path),
              _fs(fs) {
        }

        const String &path() const noexcept {
            return _path;
        }
        const Reference<FileSystem> &fs() const noexcept {
            return _fs;
        }

    private:
        String _path;
        Reference<FileSystem> _fs;
    };

public:
    static const size_t MAX_MOUNTS  = 4;

    /**
     * Constructor
     */
    explicit MountTable() noexcept
        : _count(),
          _next_id(),
          _mounts() {
    }
    ~MountTable();

    MountTable(const MountTable &ms) = delete;
    MountTable &operator=(const MountTable &ms) = delete;

    /**
     * Allocates a new id for the next filesystem
     *
     * @return the next id
     */
    size_t alloc_id() noexcept {
        return _next_id++;
    }

    /**
     * Adds the given mountpoint
     *
     * @param path the path
     * @param fs the filesystem instance
     */
    void add(const char *path, Reference<FileSystem> fs);

    /**
     * Returns the filesystem at the given path
     *
     * @param path the path
     * @return the filesystem
     */
    Reference<FileSystem> get(const char *path) {
        char tmp[256];
        return resolve(&path, tmp, sizeof(tmp));
    }

    /**
     * Resolves the given path to a mounted filesystem.
     *
     * @param path a pointer to the path; will be changed to the path relative to the mounted FS
     * @param buffer an additional buffer that can be used if the path is not absolute
     * @param bufsize the buffer size
     * @return the filesystem
     */
    Reference<FileSystem> resolve(const char **path, char *buffer, size_t bufsize);

    /**
     * Tries to resolves the given path to a mounted filesystem. That is, on error, it does not
     * throw an exception, but returns an invalid reference.
     *
     * @param path a pointer to the path; will be changed to the path relative to the mounted FS
     * @param buffer an additional buffer that can be used if the path is not absolute
     * @param bufsize the buffer size
     * @return the filesystem or an invalid reference
     */
    Reference<FileSystem> try_resolve(const char **path, char *buffer, size_t bufsize) noexcept;

    /**
     * @param id the id of the filesystem
     * @return the filesystem with given id
     */
    Reference<FileSystem> get_by_id(size_t id) noexcept;

    /**
     * Returns the mount path for the filesystem with given id
     *
     * @param id the id of the filesystem
     * @return the mount path for the filesystem (or NULL if not found)
     */
    const char *path_of_id(size_t id) noexcept;

    /**
     * @param path the path
     * @return the index of the mountpoint at given path
     */
    size_t indexof_mount(const char *path);

    /**
     * Removes the mountpoint at given path.
     *
     * @param path the path
     */
    void remove(const char *path);

    /**
     * Removes all mountpoints.
     */
    void remove_all() noexcept;

    /**
     * Delegates the mount points to <act>.
     *
     * @param act the activity to delegate the caps to
     */
    void delegate(ChildActivity &act) const;

    /**
     * Serializes the mounts of the given child activity into the given buffer
     *
     * @param act the child activity that should receive the mounts
     * @param buffer the buffer
     * @param size the capacity of the buffer
     * @return the space used
     */
    size_t serialize(ChildActivity &act, void *buffer, size_t size) const;

    /**
     * Unserializes the mounts from the buffer into a new MountTable object.
     *
     * @param buffer the buffer
     * @param size the length of the data
     * @return the mount table
     */
    static MountTable *unserialize(const void *buffer, size_t size);

    /**
     * Prints the current mounts to <os>.
     *
     * @param os the stream to write to
     */
    void print(OStream &os) const noexcept;

private:
    void do_remove(size_t i);

    size_t _count;
    size_t _next_id;
    MountPoint *_mounts[MAX_MOUNTS];
};

}
