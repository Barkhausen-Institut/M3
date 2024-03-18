/*
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
#include <base/Errors.h>
#include <base/TMIF.h>

namespace m3 {

class TMABI {
public:
    static Errors::Code call1(Operation op, word_t arg1) {
        return call2(op, arg1, 0);
    }

    static Errors::Code call2(Operation op, word_t arg1, word_t arg2) {
        register word_t a0 asm("a0") = op;
        register word_t a1 asm("a1") = arg1;
        register word_t a2 asm("a2") = arg2;
        asm volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2) : "memory");
        return static_cast<Errors::Code>(a0);
    }

    static Errors::Code call3(Operation op, word_t arg1, word_t arg2, word_t arg3) {
        register word_t a0 asm("a0") = op;
        register word_t a1 asm("a1") = arg1;
        register word_t a2 asm("a2") = arg2;
        register word_t a3 asm("a3") = arg3;
        asm volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a3) : "memory");
        return static_cast<Errors::Code>(a0);
    }

    static Errors::Code call4(Operation op, word_t arg1, word_t arg2, word_t arg3, word_t arg4) {
        register word_t a0 asm("a0") = op;
        register word_t a1 asm("a1") = arg1;
        register word_t a2 asm("a2") = arg2;
        register word_t a3 asm("a3") = arg3;
        register word_t a4 asm("a4") = arg4;
        asm volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a3), "r"(a4) : "memory");
        return static_cast<Errors::Code>(a0);
    }
};

}
