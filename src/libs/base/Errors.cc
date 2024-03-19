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

#include <base/Common.h>
#include <base/Errors.h>

namespace m3 {

static const char *errmsgs[] = {
    /* 0 */
    "No error",
    "No memory endpoint",
    "No send endpoint",
    "No receive endpoint",
    "Foreign endpoint",
    "SEND/REPLY with wrong endpoint",
    "Receiver gone",
    "Receive buffer full",
    "Replies disabled",
    "Out of bounds",
    /* 10 */
    "No credits",
    "No permission",
    "Invalid message offset",
    "Translation fault",
    "Command aborted",
    "Unknown TCU command",
    "Message too large for receive buffer",
    "Invalid reply EPs in receive EP",
    "Invalid credit EP in send EP",
    "Invalid msg_sz in send EP",
    /* 20 */
    "Timeout while waiting for memory response",
    "Timeout while waiting for NoC response",
    "Data contains page boundary",
    "Message is not 16-byte aligned",
    "TLB entry not found",
    "TLB contains only fixed entries",
    "No PMP endpoint",
    "No pending IRQ",
    "Invalid arguments",
    "Activity gone",
    /* 30 */
    "Out of memory",
    "No such file or directory",
    "Not supported",
    "No free/suitable tile",
    "Invalid ELF file",
    "No space left",
    "Object does already exist",
    "Cross-filesystem link not possible",
    "Directory not empty",
    "Is a directory",
    /* 40 */
    "Is no directory",
    "Endpoint is invalid",
    "End of file",
    "Messages are waiting to be handled",
    "Reply will be sent via upcall",
    "Commit failed",
    "Out of kernel memory",
    "Not found",
    "Not revocable",
    "Timeout",
    /* 50 */
    "Read failed",
    "Write failed",
    "UTF-8 error",
    "Bad file descriptor",
    "Invalid seek",
    "Unspecified error",

    /* Socket */
    "Invalid state",
    "Would block",
    "In progress",
    "Already in progress",
    "Socket is not connected",
    "Socket is connected",
    "Invalid checksum",
    "Socket is closed",
    "Connection failed",
    "Connection closed gracefully",
};

const char *Errors::to_string(Code code) {
    size_t idx = code;
    if(idx < ARRAY_SIZE(errmsgs))
        return errmsgs[idx];
    return "Unknown error";
}

}
