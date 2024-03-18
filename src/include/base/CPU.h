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

#include <base/Common.h>

namespace m3 {

class CPU {
public:
    static inline uint64_t read8b(uintptr_t addr);
    static inline void write8b(uintptr_t addr, uint64_t val);

    static inline word_t base_pointer();
    static inline word_t stack_pointer();

    NORETURN static inline void exit();

    static uintptr_t backtrace_step(uintptr_t bp, uintptr_t *func);

    static cycles_t elapsed_cycles();

    static inline void compute(cycles_t cycles);

    /**
     * Prevents the compiler from reordering instructions. That is, the code-generator will put all
     * preceding load and store commands before load and store commands that follow this call.
     */
    static inline void compiler_barrier() {
        asm volatile("" : : : "memory");
    }

    static inline void memory_barrier();

    static inline cycles_t gem5_debug(uint64_t msg);
};

}

#if defined(__x86_64__)
#    include <base/arch/x86_64/CPU.h>
#elif defined(__arm__)
#    include <base/arch/arm/CPU.h>
#elif defined(__riscv)
#    include <base/arch/riscv/CPU.h>
#else
#    error "Unsupported ISA"
#endif
