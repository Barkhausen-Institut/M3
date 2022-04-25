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

#include <base/Common.h>
#include <base/util/Reference.h>

#include <m3/com/Marshalling.h>
#include <m3/com/SendGate.h>
#include <m3/vfs/FileRef.h>

#include <fs/internal.h>

#include <memory>

namespace m3 {

class VFS;
class FStream;
class FileTable;
class Pager;
class ChildActivity;

/**
 * The base-class of all files. Can't be instantiated.
 */
class File : public RefCounted {
    friend class FStream;
    friend class FileTable;

protected:
    explicit File() {
    }

public:
    enum class TMode {
        RAW = 0,
        COOKED = 1,
    };

    enum Event {
        INPUT = 1,
        OUTPUT = 2,
        SIGNAL = 4,
    };

    static constexpr size_t NOTIFY_MSG_SIZE = 64;

    /**
     * The default buffer implementation
     */
    struct Buffer {
        /**
         * Creates a buffer with <_size> bytes.
         *
         * @param _size the number of bytes (0 = no buffer)
         */
        explicit Buffer(size_t _size)
            : buffer(_size ? new char[_size] : nullptr),
              size(_size),
              cur(),
              pos() {
        }

        /**
         * @return true if the buffer is empty
         */
        bool empty() noexcept {
            return cur == 0;
        }
        /**
         * Invalidates the buffer, i.e. makes it empty
         */
        void invalidate() noexcept {
            cur = 0;
        }

        /**
         * Puts the given character back into the buffer.
         *
         * @param c the character
         * @return true if successful
         */
        bool putback(char c);

        /**
         * Reads <amount> bytes from the buffer into <dst>.
         *
         * @param file the file backend
         * @param dst the destination buffer
         * @param amount the number of bytes to read
         * @return the number of read bytes (0 = EOF; -1 = would block)
         */
        ssize_t read(File *file, void *dst, size_t amount);

        /**
         * Writes <amount> bytes from <src> into the buffer.
         *
         * @param file the file backend
         * @param src the data to write
         * @param amount the number of bytes to write
         * @return the number of written bytes (0 = EOF; -1 = would block)
         */
        ssize_t write(File *file, const void *src, size_t amount);

        /**
         * Flushes the buffer. In non-blocking mode, multiple calls might be required.
         *
         * @param file the file backend
         * @return the result of the operation (-1 = would block, retry; 0 = error, 1 = all flushed)
         */
        int flush(File *file);

        std::unique_ptr<char[]> buffer;
        size_t size;
        size_t cur;
        size_t pos;
    };

    explicit File(int flags) noexcept
        : _blocking(true),
          _flags(flags),
          _fd(-1) {
    }
    File(const File &) = delete;
    File &operator=(const File &) = delete;
    virtual ~File() {
    }

    /**
     * @return the open flags
     */
    int flags() const noexcept {
        return _flags;
    }

    /**
     * @return the file descriptor
     */
    fd_t fd() const noexcept {
        return _fd;
    }

    /**
     * Retrieves information about this file
     *
     * @param info the struct to fill
     */
    void stat(FileInfo &info) const {
        Errors::Code res = try_stat(info);
        if(res != Errors::NONE)
            throw Exception(res);
    }

    /**
     * Tries to retrieve information about this file. That is, on error it does not throw an
     * exception, but returns the error code.
     *
     * @param info the struct to fill
     * @return the error on failure
     */
    virtual Errors::Code try_stat(FileInfo &info) const = 0;

    /**
     * Changes the file-position to <offset>, using <whence>.
     *
     * @param offset the offset to use
     * @param whence the seek-type (M3FS_SEEK_{SET,CUR,END}).
     * @return the new file-position
     */
    virtual size_t seek(size_t offset, int whence) = 0;

    /**
     * Reads at most <count> bytes into <buffer>.
     *
     * @param buffer the buffer to read into
     * @param count the number of bytes to read
     * @return the number of read bytes (or -1 if it would block and we are in non-blocking mode)
     */
    virtual ssize_t read(void *buffer, size_t count) = 0;

    /**
     * Writes at most <count> bytes from <buffer> into the file.
     *
     * @param buffer the data to write
     * @param count the number of bytes to write
     * @return the number of written bytes (or -1 if it would block and we are in non-blocking mode)
     */
    virtual ssize_t write(const void *buffer, size_t count) = 0;

    /**
     * Writes <count> bytes from <buffer> into the file, if possible.
     *
     * On errors or if it would block in non-blocking mode, the number of written bytes is returned.
     * In the latter case without any written bytes, -1 is returned. On errors without any written
     * bytes, 0 is returned.
     *
     * @param buffer the data to write
     * @param count the number of bytes to write
     * @return the number of written bytes (only less than count in non-blocking mode or on errors)
     */
    ssize_t write_all(const void *buffer, size_t count);

    /**
     * Truncates the file to given length.
     */
    virtual void truncate(UNUSED size_t length) {
        throw Exception(Errors::NOT_SUP);
    }

    /**
     * @return the absolute path for this file, including its mount point
     */
    virtual String path() {
        throw Exception(Errors::NOT_SUP);
    }

    /**
     * Flush the locally written data to the file system.
     */
    virtual void flush() {
    }

    /**
     * Ensure that the file is made persistent.
     */
    virtual void sync() {
    }

    /**
     * Maps the range <fileoff>..<fileoff>+<len> to *<virt> with given flags.
     *
     * @param pager the pager to use
     * @param virt the virtual address (0 = automatic); will be set to the chosen address
     * @param fileoff the file offset to start the mapping at
     * @param len the number of bytes to map
     * @param prot the protection flags (see Pager::Prot::*)
     * @param flags the mapping flags (see Pager::Flags::*)
     */
    virtual void map(Reference<Pager> &pager, goff_t *virt, size_t fileoff, size_t len,
                     int prot, int flags) const = 0;

    /**
     * @return the unique character for serialization
     */
    virtual char type() const noexcept = 0;

    /**
     * Sets the terminal mode in case the server is a terminal
     */
    virtual void set_tmode(TMode) {
        throw Exception(Errors::NOT_SUP);
    }

    /**
     * @return true if this file is operating in non-blocking mode (see set_blocking())
     */
    bool is_blocking() const noexcept {
        return _blocking;
    }

    /**
     * Sets whether this file operates in blocking or non-blocking mode. In blocking mode, read()
     * and write() will block, whereas in non-blocking mode, they return -1 in case they would block
     * (e.g., when the server needs to be asked to get access to the next input/output region).
     *
     * Note that setting the file to non-blocking might establish an additional communication
     * channel to the server, if required and not already done.
     *
     * If the server or the file type does not the non-blocking mode, an exception is thrown.
     *
     * @param blocking whether this file should operate in blocking mode
     */
    virtual void set_blocking(bool blocking) {
        if(!blocking)
            enable_notifications();
        _blocking = blocking;
    }

    /**
     * Tries to fetch a signal from the file, if any. Note that this might establish an additional
     * communication channel to the server, if required and not already done.
     *
     * If the server or the file type does not support signals, an exception is thrown.
     *
     * @return true if a signal was found
     */
    virtual bool fetch_signal() {
        throw Exception(Errors::NOT_SUP);
    }

    /**
     * Checks whether any of the given events has arrived.
     *
     * More specifically, if File::INPUT is given and reading from the file might result in
     * receiving data, the function returns true.
     *
     * This function is used by the FileWaiter that waits until any of
     * its files can make progress. Some types of files (e.g., sockets) needs to be "ticked" in
     * each iteration to actually fetch such events. For other types of files, we can just retry
     * read/write.
     */
    virtual bool check_events(UNUSED uint events) {
        // by default, files are in blocking mode and therefore we always want to try read/write.
        return true;
    }

    /**
     * Obtains a new file session from the server
     *
     * @return the new file
     */
    virtual FileRef<File> clone() const = 0;

    /**
     * Delegates this file to the given activity.
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

protected:
    /**
     * Enables notifications to work in non-blocking mode or receive signals. This might for example
     * establishes a communication channel to the server.
     */
    virtual void enable_notifications() {
        throw Exception(Errors::NOT_SUP);
    }

    virtual void remove() noexcept = 0;

    void set_fd(fd_t fd) noexcept {
        _fd = fd;
    }

    bool _blocking;
    int _flags;
    fd_t _fd;
};

}
