/*
 * Copyright (C) 2015-2016 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
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

// clang-format off
#define BEGIN_FUNC(name)        \
    .global name;               \
    .type   name, %function;    \
    name:

#define END_FUNC(name)          \
    .size   name, . - name

#if defined(__riscv)
#   if __riscv_xlen == 64
#       define WS 8
#       define smw sd
#       define lmw ld
#   else
#       define WS 4
#       define smw sw
#       define lmw lw
#   endif
#endif
