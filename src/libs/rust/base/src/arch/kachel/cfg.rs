/*
 * Copyright (C) 2020-2022 Nils Asmussen, Barkhausen Institut
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

pub const MAX_TILES: usize = 64;

#[cfg(target_vendor = "gem5")]
pub const MAX_ACTS: usize = 32;
#[cfg(target_vendor = "hw")]
pub const MAX_ACTS: usize = 16;

pub const PAGE_BITS: usize = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_BITS;
pub const PAGE_MASK: usize = PAGE_SIZE - 1;

pub const LPAGE_BITS: usize = 21;
pub const LPAGE_SIZE: usize = 1 << LPAGE_BITS;
pub const LPAGE_MASK: usize = LPAGE_SIZE - 1;

pub const RBUF_STD_ADDR: usize = 0xD000_0000;
pub const RBUF_STD_SIZE: usize = PAGE_SIZE;
pub const RBUF_ADDR: usize = RBUF_STD_ADDR + RBUF_STD_SIZE;
pub const RBUF_SIZE: usize = 0x1000_0000 - RBUF_STD_SIZE;
pub const RBUF_SIZE_SPM: usize = 0xE000;
pub const MAX_RB_SIZE: usize = 32;

#[cfg(target_arch = "riscv64")]
pub const MEM_OFFSET: usize = 0x1000_0000;
#[cfg(not(target_arch = "riscv64"))]
pub const MEM_OFFSET: usize = 0;

pub const TILEMUX_RBUF_SIZE: usize = 1 * PAGE_SIZE;

pub const TILE_MEM_BASE: usize = 0xE000_0000;

pub const MEM_CAP_END: usize = RBUF_STD_ADDR;

#[cfg(any(target_vendor = "hw", target_arch = "riscv64"))]
pub const ENV_START: usize = MEM_OFFSET + 0x8;
#[cfg(all(target_vendor = "gem5", not(target_arch = "riscv64")))]
pub const ENV_START: usize = MEM_OFFSET + 0x10_0000;
pub const ENV_SIZE: usize = PAGE_SIZE;

pub const STACK_SIZE: usize = 0x10000;

pub const FIXED_KMEM: usize = 2 * 1024 * 1024;
pub const FIXED_ROOT_MEM: usize = MOD_HEAP_SIZE + 2 * 1024 * 1024;

#[cfg(target_vendor = "hw")]
pub const TILEMUX_START: usize = MEM_OFFSET;
#[cfg(target_vendor = "gem5")]
pub const TILEMUX_START: usize = MEM_OFFSET + 0x20_0000;

pub const TILEMUX_RBUF_SPACE: usize = TILEMUX_START + 0x1F_F000;

pub const APP_HEAP_SIZE: usize = 64 * 1024 * 1024;
pub const MOD_HEAP_SIZE: usize = 4 * 1024 * 1024;

pub const SERIAL_BUF_ORD: u32 = 6;

pub const KPEX_RBUF_ORD: u32 = 6;
pub const TMUP_RBUF_ORD: u32 = 7;
pub const SYSC_RBUF_ORD: u32 = 9;
pub const UPCALL_RBUF_ORD: u32 = 6;
pub const DEF_RBUF_ORD: u32 = 8;
pub const VMA_RBUF_ORD: u32 = 6;

pub const KPEX_RBUF_SIZE: usize = 1 << KPEX_RBUF_ORD;
pub const TMUP_RBUF_SIZE: usize = 1 << TMUP_RBUF_ORD;
pub const SYSC_RBUF_SIZE: usize = 1 << SYSC_RBUF_ORD;
pub const UPCALL_RBUF_SIZE: usize = 1 << UPCALL_RBUF_ORD;
pub const DEF_RBUF_SIZE: usize = 1 << DEF_RBUF_ORD;
pub const VMA_RBUF_SIZE: usize = 1 << VMA_RBUF_ORD;
