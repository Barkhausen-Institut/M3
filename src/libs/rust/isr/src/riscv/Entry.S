#
# Copyright (C) 2020-2021 Nils Asmussen, Barkhausen Institut
#
# This file is part of M3 (Microkernel for Minimalist Manycores).
#
# M3 is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# M3 is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License version 2 for more details.
#

#include <base/Asm.h>

.extern isr_handler
.extern isr_stack

.text

BEGIN_FUNC(isr_setup)
    // setup a PMP to permit access to all memory
    li      t0, -1
    csrw    pmpaddr0, t0
    li      t0, ((0x3 << 3) | 0x7)  # NAPOT + RWX
    csrw    pmpcfg0, t0

    // enable performance counters for user+supervisor mode
    li      t0, -1
    csrw    mcounteren, t0
    csrw    scounteren, t0

    // set address to save the state on interrupts to
    csrw    sscratch, a0

    // delegate all interrupts and exceptions to supervisor mode (but exclude the timer)
    li      t1, 0xB3B
    csrw    mideleg, t1
    li      t0, -1
    csrw    medeleg, t0

    // unmask interrupts
    csrs    sie, t1
    // unset all pending interrupts
    csrw    mip, x0
    csrw    sip, x0

    // return to supervisor mode
    li      t1, 3 << 11     # clear bits first
    csrc    mstatus, t1
    li      t1, 1 << 11     # MPP = S
    csrs    mstatus, t1
    li      t1, 1 << 21     # TW = 0 (allow wfi in user mode)
    csrc    mstatus, t1
    li      t1, 1 << 1      # SIE = 0 (disable interrupts in supervisor mode)
    csrc    mstatus, t1

    // jump to 1:
    la      t0, 1f
    csrw    mepc, t0

    // set vector address
    la      t0, isr_common
    csrw    stvec, t0       # STVEC = isr_common
    csrw    mtvec, t0       # MTVEC = isr_common

    // go!
    mret
1:
    ret
END_FUNC(isr_setup)

.align 4
BEGIN_FUNC(isr_common)
    # load initial SP from SSCRATCH by swapping it with x31
    csrrw   x31, sscratch, x31

    # calculate base address
    addi    x31, x31, -(WS*34)

    # save GPRs
    smw     x1, WS*0(x31)
    smw     x2, WS*1(x31)
    smw     x3, WS*2(x31)
    smw     x4, WS*3(x31)
    smw     x5, WS*4(x31)
    smw     x6, WS*5(x31)
    smw     x7, WS*6(x31)
    smw     x8, WS*7(x31)
    smw     x9, WS*8(x31)
    smw     x10, WS*9(x31)
    smw     x11, WS*10(x31)
    smw     x12, WS*11(x31)
    smw     x13, WS*12(x31)
    smw     x14, WS*13(x31)
    smw     x15, WS*14(x31)
    smw     x16, WS*15(x31)
    smw     x17, WS*16(x31)
    smw     x18, WS*17(x31)
    smw     x19, WS*18(x31)
    smw     x20, WS*19(x31)
    smw     x21, WS*20(x31)
    smw     x22, WS*21(x31)
    smw     x23, WS*22(x31)
    smw     x24, WS*23(x31)
    smw     x25, WS*24(x31)
    smw     x26, WS*25(x31)
    smw     x27, WS*26(x31)
    smw     x28, WS*27(x31)
    smw     x29, WS*28(x31)
    smw     x30, WS*29(x31)

    # swap old sp with x31 again and store x31
    addi    s1, x31, WS*34
    mv      a0, x31
    csrrw   x31, sscratch, s1
    smw     x31, WS*30(a0)

    # save SCAUSE
    csrr    s1, scause
    smw     s1, WS*31(a0)
    # save SEPC
    csrr    s1, sepc
    smw     s1, WS*32(a0)
    # save SSTATUS
    csrr    s1, sstatus
    smw     s1, WS*33(a0)

    # start with a new stack
    la      sp, isr_stack

    # call isr_handler (state address is already in a0)
    call    isr_handler
    mv      x1, a0

    # restore SSTATUS
    lmw     s1, WS*33(x1)
    csrw    sstatus, s1
    # restore SEPC
    lmw     s1, WS*32(x1)
    csrw    sepc, s1

    # restore GPRs
    lmw     x31, WS*30(x1)
    lmw     x30, WS*29(x1)
    lmw     x29, WS*28(x1)
    lmw     x28, WS*27(x1)
    lmw     x27, WS*26(x1)
    lmw     x26, WS*25(x1)
    lmw     x25, WS*24(x1)
    lmw     x24, WS*23(x1)
    lmw     x23, WS*22(x1)
    lmw     x22, WS*21(x1)
    lmw     x21, WS*20(x1)
    lmw     x20, WS*19(x1)
    lmw     x19, WS*18(x1)
    lmw     x18, WS*17(x1)
    lmw     x17, WS*16(x1)
    lmw     x16, WS*15(x1)
    lmw     x15, WS*14(x1)
    lmw     x14, WS*13(x1)
    lmw     x13, WS*12(x1)
    lmw     x12, WS*11(x1)
    lmw     x11, WS*10(x1)
    lmw     x10, WS*9(x1)
    lmw     x9, WS*8(x1)
    lmw     x8, WS*7(x1)
    lmw     x7, WS*6(x1)
    lmw     x6, WS*5(x1)
    lmw     x5, WS*4(x1)
    lmw     x4, WS*3(x1)
    lmw     x3, WS*2(x1)
    lmw     x2, WS*1(x1)
    lmw     x1, WS*0(x1)

    sret
END_FUNC(isr_common)
