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

#pragma once

#include "../sess/Request.h"

class Links {
    Links() = delete;

public:
    static m3::Errors::Code create(Request &r, m3::INode *dir, const char *name, size_t namelen,
                                   m3::INode *inode);
    static m3::Errors::Code remove(Request &r, m3::INode *dir, const char *name, size_t namelen,
                                   bool isdir);
};
