/*
 * Copyright (C) 2015-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019-2020 Nils Asmussen, Barkhausen Institut
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

struct Regs {
    word_t a0;
    word_t ra;
    word_t sp;
    word_t fp;
    word_t s1;
    word_t s2;
    word_t s3;
    word_t s4;
    word_t s5;
    word_t s6;
    word_t s7;
    word_t s8;
    word_t s9;
    word_t s10;
    word_t s11;
} PACKED;

enum {
    T_STACK_WORDS = 4096
};

}
