/*
 * Copyright (C) 2015, Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <m3/Common.h>
#include <m3/util/Math.h>
#include <m3/Config.h>
#include <m3/Heap.h>

extern void *_bss_end;

namespace m3 {

void Heap::init() {
    uintptr_t begin = reinterpret_cast<uintptr_t>(&_bss_end);
    _begin = reinterpret_cast<Area*>(Math::round_up<size_t>(begin, sizeof(Area)));
    // TODO temporary
#if defined(__gem5__)
    uintptr_t end = Math::round_up(begin, PAGE_SIZE) + INIT_HEAP_SIZE;
    _end = reinterpret_cast<Area*>(end) - 1;
#else
    _end = reinterpret_cast<Area*>(Math::round_dn<size_t>(RT_START, sizeof(Area))) - 1;
#endif
    _end->next = 0;
    _end->prev = (_end - _begin) * sizeof(Area);
    Area *a = _begin;
    a->next = (_end - _begin) * sizeof(Area);
    a->prev = 0;
    _ready = true;
}

}
