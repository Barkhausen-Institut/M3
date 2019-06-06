/*
 * Copyright (C) 2018, Sebastian Reimers <sebastian.reimers@mailbox.tu-dresden.de>
 * Copyright (C) 2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include "FileBuffer.h"

#include <fs/internal.h>

using namespace m3;

FileBufferHead::FileBufferHead(blockno_t bno, size_t size, size_t blocksize)
    : BufferHead(bno, size),
      _data(MemGate::create_global(size * blocksize + Buffer::PRDT_SIZE, MemGate::RWX)) {
    _extents.append(new InodeExt(bno, size));
}

FileBuffer::FileBuffer(size_t blocksize, Backend *backend, size_t max_load)
    : Buffer(blocksize, backend),
      _size(),
      _max_load(max_load) {
}

size_t FileBuffer::get_extent(blockno_t bno, size_t size, capsel_t sel, int perms, size_t accessed,
                              bool load, bool dirty) {
    while(true) {
        FileBufferHead *b = FileBuffer::get(bno);
        if(b) {
            if(b->locked) {
                // wait
                SLOG(FS, "FileFuffer: Waiting for cached blocks <"
                    << b->key() << "," << b->_size << ">, for block " << bno);
                ThreadManager::get().wait_for(b->unlock);
            }
            else {
                // lock?
                lru.remove(b);
                lru.append(b);
                SLOG(FS, "FileFuffer: Found cached blocks <"
                    << b->key() << "," << b->_size << ">, for block " << bno);
                size_t len       = Math::min(size, static_cast<size_t>(b->_size - (bno - b->key())));
                Errors::Code res = m3::Syscalls::derive_mem(
                    VPE::self().sel(), sel, b->_data.sel(),
                    (bno - b->key()) * _blocksize, len * _blocksize, perms
                );

                if(res != Errors::NONE)
                    return 0;
                b->dirty |= dirty;
                return len * _blocksize;
            }
        }
        else
            break;
    }

    // load chunk into memory
    // size_t max_size = Math::min((size_t)FILE_BUFFER_SIZE, _max_load);
    size_t max_size = Math::min(FILE_BUFFER_SIZE, static_cast<size_t>(1) << accessed);
    // size_t max_size = Math::min((size_t)FILE_BUFFER_SIZE, _max_load * accessed);
    size_t load_size = Math::min(load ? max_size : FILE_BUFFER_SIZE, size);

    FileBufferHead *b;
    if((_size + load_size) > FILE_BUFFER_SIZE) {
        do {
            b = FileBuffer::get(lru.begin()->key());
            if(b->locked) {
                // wait
                SLOG(FS, "FileBuffer: Waiting for eviction of block <" << b->key() << ">");
                ThreadManager::get().wait_for(b->unlock);
            }
            else {
                SLOG(FS, "FileBuffer: Evicting block <" << b->key() << ">");
                lru.removeFirst();
                ht.remove(b);
                if(b->dirty)
                    flush_chunk(b);
                // revoke all subsets
                VPE::self().revoke(KIF::CapRngDesc(KIF::CapRngDesc::OBJ, b->_data.sel(), 1));
                _size -= b->_size;
                delete b;
            }
        }
        while((_size + load_size) > FILE_BUFFER_SIZE);
    }

    b = new FileBufferHead(bno, load_size, _blocksize);

    _size += b->_size;
    ht.insert(b);
    lru.append(b);

    // load from disk
    SLOG(FS, "FileBuffer: Allocating blocks <" << b->key() << "," << b->_size << ">"
                                               << (load ? " : loading" : ""));
    _backend->load_data(b->_data, b->key(), b->_size, load, b->unlock);

    b->locked = false;

    Errors::Code res = Syscalls::derive_mem(VPE::self().sel(), sel, b->_data.sel(), 0,
                                            load_size * _blocksize, perms);
    if(res != Errors::NONE)
        return 0;
    b->dirty = dirty;
    return load_size * _blocksize;
}

FileBufferHead *FileBuffer::get(blockno_t bno) {
    FileBufferHead *b = reinterpret_cast<FileBufferHead*>(ht.find(bno));
    if(b)
        return b;
    return nullptr;
}

void FileBuffer::flush_chunk(BufferHead *b) {
    b->locked = true;

    // TODO track the dirty regions instead of writing back the whole buffer
    SLOG(FS, "FileBuffer: Write back blocks <" << b->key() << "," << b->_size << ">");
    _backend->store_data(b->key(), b->_size, b->unlock);

    b->dirty  = false;
    b->locked = false;
}

void FileBuffer::flush() {
    while(!ht.empty()) {
        FileBufferHead *b = reinterpret_cast<FileBufferHead *>(ht.remove_root());
        if(b->dirty)
            flush_chunk(b);
    }
}
