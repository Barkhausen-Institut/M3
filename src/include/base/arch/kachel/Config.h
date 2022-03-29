/*
 * Copyright (C) 2016-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
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

#define PAGE_BITS           12
#ifndef PAGE_SIZE
#   define PAGE_SIZE        (static_cast<size_t>(1) << PAGE_BITS)
#endif
#define PAGE_MASK           (PAGE_SIZE - 1)

#define LPAGE_BITS          21
#define LPAGE_SIZE          (static_cast<size_t>(1) << LPAGE_BITS)
#define LPAGE_MASK          (LPAGE_SIZE - 1)

#define APP_HEAP_SIZE       (64 * 1024 * 1024)
#define EPMEM_SIZE          0

#if defined(__hw__)
#   define TOTAL_EPS        128
#   define AVAIL_EPS        TOTAL_EPS
#   define MAX_ACTS         8
#else
#   define TOTAL_EPS        192
#   define AVAIL_EPS        TOTAL_EPS
#   define MAX_ACTS         32
#endif

#if defined(__riscv)
#   define MEM_OFFSET       0x10000000
#else
#   define MEM_OFFSET       0
#endif

// (RISC-V) physical memory layout:
// +----------------------------+ 0x0
// |         devices etc.       |
// +----------------------------+ 0x10000000
// |        TileMux code        |
// +----------------------------+ 0x10060000
// |           app code         |
// +----------------------------+ 0x10100000
// |     env + TileMux data     |
// +----------------------------+ 0x10160000
// |          app data          |
// +----------------------------+ 0x101E0000
// |          app stack         |
// +----------------------------+ 0x101F0000
// |      app recv buffers      |
// +----------------------------+ 0x101FF000
// |    TileMux recv buffers    |
// +----------------------------+ 0x10200000
// |            ...             |
// +----------------------------+ 0xF0000000
// |          TCU MMIO          |
// +----------------------------+ 0xF0002000

// (RISC-V) virtual memory layout:
// +----------------------------+ 0x0
// |            ...             |
// +----------------------------+ 0x10100000
// |            env             |
// +----------------------------+ 0x10101000
// |            ...             |
// +----------------------------+ 0x10200000
// |     TileMux code+data      |
// +----------------------------+ 0x103FF000
// |    TileMux recv buffers    |
// +----------------------------+ 0x10400000
// |       app code+data        |
// |            ...             |
// +----------------------------+ 0xCFFF0000
// |          app stack         |
// +----------------------------+ 0xD0000000
// |      std recv buffers      |
// +----------------------------+ 0xD0001000
// |        recv buffers        |
// |            ...             |
// +----------------------------+ 0xE0000000
// |     Tile's own phys mem    |
// +----------------------------+ 0xF0000000
// |          TCU MMIO          |
// +----------------------------+ 0xF0002000

#define ENV_SIZE            PAGE_SIZE
#define ENV_END             (ENV_START + ENV_SIZE)

#define STACK_SIZE          0x50000

#define RBUF_STD_ADDR       0xD0000000
#define RBUF_STD_SIZE       PAGE_SIZE
#define RBUF_ADDR           (RBUF_STD_ADDR + RBUF_STD_SIZE)
#define RBUF_SIZE           (0x10000000 - RBUF_STD_SIZE)
#define RBUF_SIZE_SPM       0xE000

#if defined(__hw__)
#   define TILEMUX_CODE_START (MEM_OFFSET + 0x1000)
#   define ENV_START        (MEM_OFFSET + 0x8)
#else
#   define TILEMUX_CODE_START (MEM_OFFSET + 0x200000)
#   if defined(__riscv)
#       define ENV_START    (MEM_OFFSET + 0x8)
#   else
#       define ENV_START    (MEM_OFFSET + 0x100000)
#   endif
#endif

#define TILEMUX_RBUF_SIZE   0x1000

#define KPEX_RBUF_ORDER     6
#define KPEX_RBUF_SIZE      (1 << KPEX_RBUF_ORDER)

#define TMUP_RBUF_ORDER     6
#define TMUP_RBUF_SIZE      (1 << TMUP_RBUF_ORDER)

#define SYSC_RBUF_ORDER     9
#define SYSC_RBUF_SIZE      (1 << SYSC_RBUF_ORDER)

#define UPCALL_RBUF_ORDER   6
#define UPCALL_RBUF_SIZE    (1 << UPCALL_RBUF_ORDER)

#define DEF_RBUF_ORDER      8
#define DEF_RBUF_SIZE       (1 << DEF_RBUF_ORDER)

#define VMA_RBUF_ORDER      6
#define VMA_RBUF_SIZE       (1 << VMA_RBUF_ORDER)
