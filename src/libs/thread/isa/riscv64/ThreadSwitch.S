/*
 * Copyright (C) 2016-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <base/Asm.h>

# void thread_switch(m3::Thread::Regs *old, m3::Thread::Regs *new)
BEGIN_FUNC(thread_switch)
    # save registers
    sd ra, 8(a0)
    sd sp, 16(a0)
    sd fp, 24(a0)
    sd s1, 32(a0)
    sd s2, 40(a0)
    sd s3, 48(a0)
    sd s4, 56(a0)
    sd s5, 64(a0)
    sd s6, 72(a0)
    sd s7, 80(a0)
    sd s8, 88(a0)
    sd s9, 96(a0)
    sd s10, 104(a0)
    sd s11, 112(a0)

    # restore registers
    ld ra, 8(a1)
    ld sp, 16(a1)
    ld fp, 24(a1)
    ld s1, 32(a1)
    ld s2, 40(a1)
    ld s3, 48(a1)
    ld s4, 56(a1)
    ld s5, 64(a1)
    ld s6, 72(a1)
    ld s7, 80(a1)
    ld s8, 88(a1)
    ld s9, 96(a1)
    ld s10, 104(a1)
    ld s11, 112(a1)

    # not saved, but restored for the thread argument
    ld a0, 0(a1)

    ret
END_FUNC(thread_switch)
