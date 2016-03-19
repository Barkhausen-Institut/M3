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

#include <base/Common.h>
#include <base/stream/Serial.h>

using namespace m3;

int main() {
    volatile float f = 12.43;
    f *= 3;
    f += 1;
    Serial::get() << "f = " << f << "\n";
    f /= 13;
    Serial::get() << "f = " << fmt(f, 12, 5) << "\n";
    Serial::get() << "f = " << -1.2345f << "\n";
    return 0;
}
