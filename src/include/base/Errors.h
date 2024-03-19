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

#include <base/Types.h>
#include <base/stream/Format.h>

namespace m3 {

/**
 * The error codes for M3
 */
struct Errors {
    enum Code : int32_t {
        SUCCESS,
        // TCU errors
        NO_MEP,
        NO_SEP,
        NO_REP,
        FOREIGN_EP,
        SEND_REPLY_EP,
        RECV_GONE,
        RECV_NO_SPACE,
        REPLIES_DISABLED,
        OUT_OF_BOUNDS,
        NO_CREDITS,
        NO_PERM,
        INV_MSG_OFF,
        TRANSLATION_FAULT,
        ABORT,
        UNKNOWN_CMD,
        RECV_OUT_OF_BOUNDS,
        RECV_INV_RPL_EPS,
        SEND_INV_CRD_EP,
        SEND_INV_MSG_SZ,
        TIMEOUT_MEM,
        TIMEOUT_NOC,
        PAGE_BOUNDARY,
        MSG_UNALIGNED,
        TLB_MISS,
        TLB_FULL,
        NO_PMP_EP,
        NO_IRQ,
        // SW errors
        INV_ARGS,
        ACT_GONE,
        OUT_OF_MEM,
        NO_SUCH_FILE,
        NOT_SUP,
        NO_FREE_TILE,
        INVALID_ELF,
        NO_SPACE,
        EXISTS,
        XFS_LINK,
        DIR_NOT_EMPTY,
        IS_DIR,
        IS_NO_DIR,
        EP_INVALID,
        END_OF_FILE,
        MSGS_WAITING,
        UPCALL_REPLY,
        COMMIT_FAILED,
        NO_KMEM,
        NOT_FOUND,
        NOT_REVOCABLE,
        TIMEOUT,
        READ_FAILED,
        WRITE_FAILED,
        UTF8_ERROR,
        BAD_FD,
        SEEK_PIPE,
        UNSPECIFIED,
        // networking
        INV_STATE,
        WOULD_BLOCK,
        IN_PROGRESS,
        ALREADY_IN_PROGRESS,
        NOT_CONNECTED,
        IS_CONNECTED,
        INV_CHECKSUM,
        SOCKET_CLOSED,
        CONNECTION_FAILED,
        CONN_CLOSED,
    };

    /**
     * @param code the error code
     * @return the statically allocated error message for <code>
     */
    static const char *to_string(Code code);
};

template<>
struct Formatter<Errors::Code> {
    void format(OStream &os, const FormatSpecs &, const Errors::Code &e) const {
        format_to(os, "{} ({})"_cf, Errors::to_string(e), static_cast<int32_t>(e));
    }
};

}
