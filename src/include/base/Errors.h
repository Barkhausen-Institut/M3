/*
 * Copyright (C) 2016-2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <base/Types.h>

namespace m3 {

/**
 * The error codes for M3
 */
struct Errors {
    enum Code : int32_t {
        NONE,
        // TCU errors
        MISS_CREDITS,
        NO_RING_SPACE,
        PAGEFAULT,
        INV_EP,
        ABORT,
        INV_MSG,
        INV_ARGS,
        NO_PERM,
        // SW errors
        VPE_GONE,
        OUT_OF_MEM,
        NO_SUCH_FILE,
        NOT_SUP,
        NO_FREE_PE,
        INVALID_ELF,
        NO_SPACE,
        EXISTS,
        XFS_LINK,
        DIR_NOT_EMPTY,
        IS_DIR,
        IS_NO_DIR,
        EP_INVALID,
        RECV_GONE,
        END_OF_FILE,
        MSGS_WAITING,
        UPCALL_REPLY,
        COMMIT_FAILED,
        NO_KMEM,
        NOT_FOUND,
        NOT_REVOCABLE,
        TIMEOUT,
        // Socket
        IN_USE,
        INV_STATE,
        WOULD_BLOCK,
        IN_PROGRESS,
        ALREADY_IN_PROGRESS,
        NOT_CONNECTED,
        IS_CONNECTED,
        CONN_ABORT,
        CONN_RESET,
        CONN_CLOSED,
        NET_UNREACHABLE,
        SOCKET_CLOSED,
    };

    /**
     * @param code the error code
     * @return the statically allocated error message for <code>
     */
    static const char *to_string(Code code);
};

}
