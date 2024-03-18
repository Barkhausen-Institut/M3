/*
 * Copyright (C) 2021 Nils Asmussen, Barkhausen Institut
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

#if __riscv_xlen == 32
EXTERN_C void gem5_writefile(const char *str, uint64_t len, uint64_t offset, uint64_t file) {
    register word_t r0 asm("a0") = reinterpret_cast<word_t>(str);
    register word_t r1 asm("a1") = static_cast<word_t>(len);
    register word_t r2 asm("a2") = static_cast<word_t>(offset);
    register word_t r3 asm("a3") = static_cast<word_t>(file);
    asm volatile(".long 0x9E00007B" : : "r"(r0), "r"(r1), "r"(r2), "r"(r3));
}

EXTERN_C ssize_t gem5_readfile(char *dst, uint64_t max, uint64_t offset) {
    register word_t r0 asm("a0") = reinterpret_cast<word_t>(dst);
    register word_t r1 asm("a1") = static_cast<word_t>(max);
    register word_t r2 asm("a2") = static_cast<word_t>(offset);
    asm volatile(".long 0xA000007B" : "+r"(r0) : "r"(r1), "r"(r2));
    uint64_t res = static_cast<uint64_t>(r0) | static_cast<uint64_t>(r1) << 32;
    return static_cast<ssize_t>(res);
}
#endif
