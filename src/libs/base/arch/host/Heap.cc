/*
 * Copyright (C) 2016-2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <base/Common.h>
#include <base/Config.h>
#include <base/Heap.h>
#include <base/Panic.h>

#include <malloc.h>

#if !defined(__SANITIZE_ADDRESS__)
static void ensure_inited() {
    static bool done = false;
    if(!done) {
        m3::Heap::init();
        done = true;
    }
}

/* these functions are defined as weak, so that we can simply overwrite them here */
USED void *malloc(size_t size) {
    ensure_inited();
    return heap_alloc(size);
}
USED void *calloc(size_t n, size_t size) {
    ensure_inited();
    return heap_calloc(n, size);
}
USED void *realloc(void *p, size_t size) {
    ensure_inited();
    return heap_realloc(p, size);
}
USED void free(void *p) {
    ensure_inited();
    return heap_free(p);
}
#endif

namespace m3 {

void Heap::init_arch() {
    heap_init(Env::heap_start(), Env::heap_start() + HEAP_SIZE);
}

}
