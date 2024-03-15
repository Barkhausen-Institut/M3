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
    addi    x31, x31, -(8*34)

    # save GPRs
    sd      x1, 8*0(x31)
    sd      x2, 8*1(x31)
    sd      x3, 8*2(x31)
    sd      x4, 8*3(x31)
    sd      x5, 8*4(x31)
    sd      x6, 8*5(x31)
    sd      x7, 8*6(x31)
    sd      x8, 8*7(x31)
    sd      x9, 8*8(x31)
    sd      x10, 8*9(x31)
    sd      x11, 8*10(x31)
    sd      x12, 8*11(x31)
    sd      x13, 8*12(x31)
    sd      x14, 8*13(x31)
    sd      x15, 8*14(x31)
    sd      x16, 8*15(x31)
    sd      x17, 8*16(x31)
    sd      x18, 8*17(x31)
    sd      x19, 8*18(x31)
    sd      x20, 8*19(x31)
    sd      x21, 8*20(x31)
    sd      x22, 8*21(x31)
    sd      x23, 8*22(x31)
    sd      x24, 8*23(x31)
    sd      x25, 8*24(x31)
    sd      x26, 8*25(x31)
    sd      x27, 8*26(x31)
    sd      x28, 8*27(x31)
    sd      x29, 8*28(x31)
    sd      x30, 8*29(x31)

    # swap old sp with x31 again and store x31
    addi    s1, x31, 8*34
    mv      a0, x31
    csrrw   x31, sscratch, s1
    sd      x31, 8*30(a0)

    # save SCAUSE
    csrr    s1, scause
    sd      s1, 8*31(a0)
    # save SEPC
    csrr    s1, sepc
    sd      s1, 8*32(a0)
    # save SSTATUS
    csrr    s1, sstatus
    sd      s1, 8*33(a0)

    # start with a new stack
    la      sp, isr_stack

    # call isr_handler (state address is already in a0)
    call    isr_handler
    mv      x1, a0

    # restore SSTATUS
    ld      s1, 8*33(x1)
    csrw    sstatus, s1
    # restore SEPC
    ld      s1, 8*32(x1)
    csrw    sepc, s1

    # restore GPRs
    ld      x31, 8*30(x1)
    ld      x30, 8*29(x1)
    ld      x29, 8*28(x1)
    ld      x28, 8*27(x1)
    ld      x27, 8*26(x1)
    ld      x26, 8*25(x1)
    ld      x25, 8*24(x1)
    ld      x24, 8*23(x1)
    ld      x23, 8*22(x1)
    ld      x22, 8*21(x1)
    ld      x21, 8*20(x1)
    ld      x20, 8*19(x1)
    ld      x19, 8*18(x1)
    ld      x18, 8*17(x1)
    ld      x17, 8*16(x1)
    ld      x16, 8*15(x1)
    ld      x15, 8*14(x1)
    ld      x14, 8*13(x1)
    ld      x13, 8*12(x1)
    ld      x12, 8*11(x1)
    ld      x11, 8*10(x1)
    ld      x10, 8*9(x1)
    ld      x9, 8*8(x1)
    ld      x8, 8*7(x1)
    ld      x7, 8*6(x1)
    ld      x6, 8*5(x1)
    ld      x5, 8*4(x1)
    ld      x4, 8*3(x1)
    ld      x3, 8*2(x1)
    ld      x2, 8*1(x1)
    ld      x1, 8*0(x1)

    sret
END_FUNC(isr_common)
