/*
 * Copyright (C) 2015-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
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
#include <base/time/Instant.h>

namespace m3 {

/**
 * Simple way of pseudo random number generation.
 *
 * Source: http://en.wikipedia.org/wiki/Linear_congruential_generator
 */
class Random {
public:
    /**
     * Creates a new random number generator with given seed
     *
     * @param seed the seed to use (default = current timestamp)
     */
    explicit Random(uint seed = TimeInstant::now().as_nanos()) noexcept
        : _a(1103515245),
          _c(12345),
          _last(seed) {
    }

    /**
     * @return the next random number
     */
    int get() noexcept {
        _last = _a * _last + _c;
        return (_last / 65536) % 32768;
    }

private:
    uint _a;
    uint _c;
    uint _last;
};

}
