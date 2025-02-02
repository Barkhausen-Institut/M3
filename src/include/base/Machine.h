/*
 * Copyright (C) 2015-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019-2021 Nils Asmussen, Barkhausen Institut
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

namespace m3 {

/**
 * Low-level machine-specific functions.
 */
class Machine {
    Machine() = delete;

public:
    /**
     * Shuts down the machine
     */
    static NORETURN void shutdown();

    /**
     * Writes <len> bytes from <str> to the serial device.
     *
     * @param str the string to write
     * @param len the length of the string
     * @return the number of written bytes on success
     */
    static ssize_t write(const char *str, size_t len);

    /**
     * Resets the statistics
     */
    static void reset_stats();

    /**
     * Dumps the statistics to file
     */
    static void dump_stats();
};

}
