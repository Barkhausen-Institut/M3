/*
 * Copyright (C) 2016-2018 Nils Asmussen <nils@os.inf.tu-dresmwen.de>
 * Economic rights: Technische Universitaet Dresmwen (Germany)
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
    smw ra, 1*WS(a0)
    smw sp, 2*WS(a0)
    smw fp, 3*WS(a0)
    smw s1, 4*WS(a0)
    smw s2, 5*WS(a0)
    smw s3, 6*WS(a0)
    smw s4, 7*WS(a0)
    smw s5, 8*WS(a0)
    smw s6, 9*WS(a0)
    smw s7, 10*WS(a0)
    smw s8, 11*WS(a0)
    smw s9, 12*WS(a0)
    smw s10, 13*WS(a0)
    smw s11, 14*WS(a0)

    # restore registers
    lmw ra, 1*WS(a1)
    lmw sp, 2*WS(a1)
    lmw fp, 3*WS(a1)
    lmw s1, 4*WS(a1)
    lmw s2, 5*WS(a1)
    lmw s3, 6*WS(a1)
    lmw s4, 7*WS(a1)
    lmw s5, 8*WS(a1)
    lmw s6, 9*WS(a1)
    lmw s7, 10*WS(a1)
    lmw s8, 11*WS(a1)
    lmw s9, 12*WS(a1)
    lmw s10, 13*WS(a1)
    lmw s11, 14*WS(a1)

    # not saved, but restored for the thread argument
    lmw a0, 0(a1)

    ret
END_FUNC(thread_switch)
