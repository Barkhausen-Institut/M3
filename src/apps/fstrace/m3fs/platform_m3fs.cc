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

#include <m3/stream/Standard.h>

#include <stdarg.h>

#include "fsapi_m3fs.h"
#include "platform.h"

/*
 * *************************************************************************
 */

void Platform::init(int /*argc*/, const char * const * /*argv*/) {

}


FSAPI *Platform::fsapi(const char *root) {
    return new FSAPI_M3FS(root);
}


void Platform::shutdown() {

}


void Platform::checkpoint_fs() {

}


void Platform::sync_fs() {

}


void Platform::drop_caches() {

}


void Platform::log(const char *msg) {
    m3::cout << msg << "\n";
}

void Platform::logf(UNUSED const char *fmt, ...) {
#if defined(__host__)
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
#endif
}
