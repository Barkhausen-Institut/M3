/*
 * Copyright (C) 2019 Nils Asmussen, Barkhausen Institut
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

#include <m3/stream/Standard.h>

extern int failed;

#define WVPERF(name, bench)                                                 \
    m3::cout << "! " << __FILE__ << ":" << __LINE__                         \
             << "  PERF \"" << name << "\": " << bench << "\n"

#define WVASSERT(val) ({                                                    \
        if(!(val)) {                                                        \
            failed++;                                                       \
            m3::cout << "! " << __FILE__ << ":" << __LINE__                 \
                     << "  expected true, got "                             \
                     << #val << " (false) FAILED\n";                        \
        }                                                                   \
    })

#define WVASSERTEQ(a, b) ({                                                 \
        auto _a = a;                                                        \
        auto _b = b;                                                        \
        if(_a != _b) {                                                      \
            failed++;                                                       \
            m3::cout << "! " << __FILE__ << ":" << __LINE__                 \
                     << "  \"" << _a << "\" == \"" << _b << "\" FAILED\n";  \
        }                                                                   \
    })

#define WVASSERTSTREQ(a, b) ({                                              \
        auto _a = (const char*)a;                                           \
        auto _b = (const char*)b;                                           \
        if((_a == nullptr) != (_b == nullptr) ||                            \
            (_a && strcmp(_a, _b) != 0)) {                                  \
            failed++;                                                       \
            m3::cout << "! " << __FILE__ << ":" << __LINE__                 \
                     << "  \"" << _a << "\" == \"" << _b << "\" FAILED\n";  \
        }                                                                   \
    })

static inline void WVASSERTERR(m3::Errors::Code err, std::function<void()> func) {
    try {
        func();
        WVASSERT(false);
    }
    catch(const m3::Exception &e) {
        WVASSERTEQ(e.code(), err);
    }
}
