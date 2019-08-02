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

#pragma once

#include <base/Common.h>

#include <m3/stream/FStream.h>

namespace m3 {

/**
 * A directory which allows to iterate over the directory entries.
 */
class Dir {
public:
    struct Entry {
        static constexpr size_t MAX_NAME_LEN    = 28;

        inodeno_t nodeno;
        char name[MAX_NAME_LEN];
    } PACKED;

    /**
     * Opens the given directory
     *
     * @param path the path of the directory
     * @param flags the desired flags (FILE_R by default)
     */
    explicit Dir(const char *path, int flags = FILE_R) : _f(path, flags, sizeof(Entry) * 16) {
    }

    /**
     * Retrieves the file information about this directory
     *
     * @param info where to store the information
     */
    void stat(FileInfo &info) const {
        _f.file()->stat(info);
    }

    /**
     * Reads the next directory entry into <e>.
     *
     * @param e the entry to write to
     * @return true if an entry has been read; false indicates EOF
     */
    bool readdir(Entry &e);

    /**
     * Resets the file position to the beginning
     */
    void reset() {
        _f.seek(0, M3FS_SEEK_SET);
        _f.clear_state();
    }

private:
    FStream _f;
};

}
