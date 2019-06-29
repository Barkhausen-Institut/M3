/*
 * Copyright (C) 2015-2016, Nils Asmussen <nils@os.inf.tu-dresden.de>
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
#include <string.h>

char *strstr(const char *str1, const char *str2) {
    char *res = nullptr;
    const char *sub;
    /* handle special case to prevent looping the string */
    if(!*str2)
        return const_cast<char*>(str1);
    while(*str1) {
        /* matching char? */
        if(*str1++ == *str2) {
            res = const_cast<char*>(--str1);
            sub = str2;
            /* continue until the strings don't match anymore */
            while(*sub && *str1 == *sub) {
                str1++;
                sub++;
            }
            /* complete substring matched? */
            if(!*sub)
                return res;
        }
    }
    return nullptr;
}
