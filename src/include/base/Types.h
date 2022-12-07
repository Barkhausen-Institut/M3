/*
 * Copyright (C) 2015-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <stdint.h>

typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef long long llong;
typedef unsigned long long ullong;

#if defined(__arm__)
typedef unsigned int size_t;
typedef int ssize_t;
#else
typedef unsigned long size_t;
typedef long ssize_t;
#endif

typedef unsigned long word_t;
typedef uint64_t label_t;
typedef uint64_t capsel_t;
typedef int fd_t;
typedef uint64_t cycles_t;

typedef ulong epid_t;
typedef ulong tileid_t;
typedef uint16_t actid_t;
typedef uint64_t goff_t;
typedef uint64_t event_t;
typedef uint64_t xfer_t;
