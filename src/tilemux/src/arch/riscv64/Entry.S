#
# Copyright (C) 2015-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
# Economic rights: Technische Universitaet Dresden (Germany)
#
# Copyright (C) 2019-2022 Nils Asmussen, Barkhausen Institut
#
# This file is part of M3 (Microkernel-based SysteM for Heterogeneous Manycores).
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
#include <base/Config.h>

.extern init
.extern isr_stack

BEGIN_FUNC(_start)
    la      sp, isr_stack
    call    init

    // return to user mode
    li      a0, 1 << 8
    csrc    sstatus, a0
    // enable interrupts
    li      a0, 1 << 5
    csrs    sstatus, a0

    // jump to sleep function
    la      a0, sleep
    csrw    sepc, a0

    // go!
    sret
END_FUNC(_start)

// fn _shutdown()
BEGIN_FUNC(_shutdown)
    // remove potentially pending interrupts
    csrw    sip, x0
    // disable supervisor interrupts
    li      t0, 1 << 5
    csrc    sstatus, t0
1:
    wfi
    j       1b
END_FUNC(_shutdown)

// fn save_fpu(state: &mut FPUState)
BEGIN_FUNC(save_fpu)
    fsd     f0, 8*0(a0)
    fsd     f1, 8*1(a0)
    fsd     f2, 8*2(a0)
    fsd     f3, 8*3(a0)
    fsd     f4, 8*4(a0)
    fsd     f5, 8*5(a0)
    fsd     f6, 8*6(a0)
    fsd     f7, 8*7(a0)
    fsd     f8, 8*8(a0)
    fsd     f9, 8*9(a0)
    fsd     f10, 8*10(a0)
    fsd     f11, 8*11(a0)
    fsd     f12, 8*12(a0)
    fsd     f13, 8*13(a0)
    fsd     f14, 8*14(a0)
    fsd     f15, 8*15(a0)
    fsd     f16, 8*16(a0)
    fsd     f17, 8*17(a0)
    fsd     f18, 8*18(a0)
    fsd     f19, 8*19(a0)
    fsd     f20, 8*20(a0)
    fsd     f21, 8*21(a0)
    fsd     f22, 8*22(a0)
    fsd     f23, 8*23(a0)
    fsd     f24, 8*24(a0)
    fsd     f25, 8*25(a0)
    fsd     f26, 8*26(a0)
    fsd     f27, 8*27(a0)
    fsd     f28, 8*28(a0)
    fsd     f29, 8*29(a0)
    fsd     f30, 8*30(a0)
    fsd     f31, 8*31(a0)
    csrr    t0, fcsr
    sd      t0, 8*32(a0)
    ret
END_FUNC(save_fpu)

// fn restore_fpu(state: &FPUState)
BEGIN_FUNC(restore_fpu)
    fld     f0, 8*0(a0)
    fld     f1, 8*1(a0)
    fld     f2, 8*2(a0)
    fld     f3, 8*3(a0)
    fld     f4, 8*4(a0)
    fld     f5, 8*5(a0)
    fld     f6, 8*6(a0)
    fld     f7, 8*7(a0)
    fld     f8, 8*8(a0)
    fld     f9, 8*9(a0)
    fld     f10, 8*10(a0)
    fld     f11, 8*11(a0)
    fld     f12, 8*12(a0)
    fld     f13, 8*13(a0)
    fld     f14, 8*14(a0)
    fld     f15, 8*15(a0)
    fld     f16, 8*16(a0)
    fld     f17, 8*17(a0)
    fld     f18, 8*18(a0)
    fld     f19, 8*19(a0)
    fld     f20, 8*20(a0)
    fld     f21, 8*21(a0)
    fld     f22, 8*22(a0)
    fld     f23, 8*23(a0)
    fld     f24, 8*24(a0)
    fld     f25, 8*25(a0)
    fld     f26, 8*26(a0)
    fld     f27, 8*27(a0)
    fld     f28, 8*28(a0)
    fld     f29, 8*29(a0)
    fld     f30, 8*30(a0)
    fld     f31, 8*31(a0)
    ld      t0, 8*32(a0)
    csrw    fcsr, t0
    ret
END_FUNC(restore_fpu)

.section .user_text

BEGIN_FUNC(sleep)
    la      a0, ENV_START
    // load platform from environment
    ld      a0, 0(a0)
    // skip wfi on hw (TODO why does that not work?)
1:  bnez    a0, 2f
    wfi
2:
    j       1b
END_FUNC(sleep)
