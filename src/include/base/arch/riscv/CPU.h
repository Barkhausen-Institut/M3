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

#include <base/CPU.h>
#include <base/Common.h>

#if defined(__hw__) || defined(__hw22__) || defined(__hw23__)
#    define NEED_ALIGNED_MEMACC 1
#else
#    define NEED_ALIGNED_MEMACC 0
#endif

namespace m3 {

inline uint64_t CPU::read8b(uintptr_t addr) {
#if __riscv_xlen == 64
    uint64_t res;
    asm volatile("ld %0, (%1)" : "=r"(res) : "r"(addr));
    return res;
#else
    uint32_t resh, resl;
    asm volatile(
        "lw %0, 4(%2)\n"
        "lw %1, 0(%2)\n"
        : "=&r"(resh), "=r"(resl)
        : "r"(addr));
    return static_cast<uint64_t>(resh) << 32 | resl;
#endif
}

inline void CPU::write8b(uintptr_t addr, uint64_t val) {
#if __riscv_xlen == 64
    asm volatile("sd %0, (%1)" : : "r"(val), "r"(addr) : "memory");
#else
    // ensure that we write the upper half first as the lower half might trigger an action (e.g.,
    // the command register)
    asm volatile(
        "sw %0, 4(%2)\n"
    // fence is not supported by PicoRV32
#    if defined(__gem5__)
        "fence\n"
#    endif
        "sw %1, 0(%2)\n"
        :
        : "r"(val >> 32), "r"(val & 0xFFFFFFFF), "r"(addr)
        : "memory");
#endif
}

ALWAYS_INLINE word_t CPU::base_pointer() {
    word_t val;
    asm volatile("mv %0, fp;" : "=r"(val));
    return val;
}

ALWAYS_INLINE word_t CPU::stack_pointer() {
    word_t val;
    asm volatile("mv %0, sp;" : "=r"(val));
    return val;
}

inline cycles_t CPU::elapsed_cycles() {
#if __riscv_xlen == 64
    cycles_t res;
    asm volatile("rdcycle %0" : "=r"(res) : : "memory");
    return res;
#else
    uint32_t cycles_hi0, cycles_hi1, cycles_lo;
    asm volatile(
        "rdcycleh %0\n"
        "rdcycle %1\n"
        "rdcycleh %2\n"
        "sub %0, %0, %2\n"
        "seqz %0, %0\n"
        "sub %0, zero, %0\n"
        "and %1, %1, %0\n"
        : "=r"(cycles_hi0), "=r"(cycles_lo), "=r"(cycles_hi1));
    return (static_cast<uint64_t>(cycles_hi1) << 32) | cycles_lo;
#endif
}

inline uintptr_t CPU::backtrace_step(uintptr_t bp, uintptr_t *func) {
    *func = reinterpret_cast<uintptr_t *>(bp)[-1];
    return reinterpret_cast<uintptr_t *>(bp)[-2];
}

inline void CPU::compute(cycles_t cycles) {
    cycles_t iterations = cycles / 2;
    asm volatile(
        ".align 4;"
        "1: addi %0, %0, -1;"
        "bnez %0, 1b;"
        // let the compiler know that we change the value of cycles
        // as it seems, inputs are not expected to change
        : "=r"(iterations)
        : "0"(iterations));
}

inline void CPU::memory_barrier() {
#if __riscv_xlen == 64 || defined(__gem5__)
    asm volatile("fence" : : : "memory");
#endif
}

inline cycles_t CPU::gem5_debug(uint64_t msg) {
    register cycles_t a0 asm("a0") = msg;
    asm volatile(".long 0xC600007B" : "+r"(a0));
    return a0;
}
}
