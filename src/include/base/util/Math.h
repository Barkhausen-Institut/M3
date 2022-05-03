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

#include <base/Common.h>

namespace m3 {

class Math {
    union FloatInt {
        constexpr FloatInt(float _f) : f(_f) {
        }
        constexpr FloatInt(uint32_t _i) : i(_i) {
        }
        float f;
        uint32_t i;
    };

public:
    template<typename T>
    static constexpr T min(T a, T b) {
        return a < b ? a : b;
    }

    template<typename T>
    static constexpr T max(T a, T b) {
        return a < b ? b : a;
    }

    template<typename T>
    static uint bits_set(T value) {
        uint count = 0;
        for(size_t i = 0; i < sizeof(value) * 8; ++i) {
            if(value & (1UL << i))
                count++;
        }
        return count;
    }

    /**
     * Assuming that <startx> < <endx> and <endx> is not included (that means with start=0 and
     * end=10 0 .. 9 is used), the macro determines whether the two ranges overlap anywhere.
     */
    static constexpr bool overlap(uintptr_t start1, uintptr_t end1, uintptr_t start2,
                                  uintptr_t end2) {
        return (start1 >= start2 && start1 < end2) || // start in range
               (end1 > start2 && end1 <= end2) ||     // end in range
               (start1 < start2 && end1 > end2);      // complete overlapped
    }

    template<typename T>
    static constexpr T round_up(T value, T align) {
        return (value + align - 1) & ~(align - 1);
    }

    template<typename T>
    static constexpr T round_dn(T value, T align) {
        return value & ~(align - 1);
    }

    template<typename T>
    static constexpr bool is_aligned(T ptr, size_t align) {
        return ((uintptr_t)ptr & (align - 1)) == 0;
    }

    static float sqrt(float n) {
        // Source: https://en.wikipedia.org/wiki/Methods_of_computing_square_roots
        uint32_t val_int = *reinterpret_cast<uint32_t *>(&n);
        val_int -= 1 << 23; /* Subtract 2^m. */
        val_int >>= 1;      /* Divide by 2. */
        val_int += 1 << 29; /* Add ((b + 1) / 2) * 2^m. */
        return *reinterpret_cast<float *>(&val_int);
    }

    static constexpr float nan() {
        return FloatInt(static_cast<uint32_t>(0x7FC0'0000)).f;
    }
    static constexpr float inf() {
        return FloatInt(static_cast<uint32_t>(0x7F80'0000)).f;
    }

    static constexpr bool is_neg(float x) {
        return FloatInt(x).i & 0x8000'0000;
    }
    static constexpr int is_nan(float x) {
        return ((FloatInt(x).i >> 23) & 0xFF) == 0xFF && (FloatInt(x).i & 0x7F'FFFF) != 0;
    }
    static constexpr int is_inf(float x) {
        return (FloatInt(x).i & 0x7FFF'FFFF) == 0x7F80'0000;
    }

private:
    Math();
};

}
