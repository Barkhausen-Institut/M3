/*
 * Copyright (C) 2020 Nils Asmussen, Barkhausen Institut
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

#include <m3/Test.h>

#include "../unittests.h"

using namespace m3;

static const size_t LARGE_BUF_SIZE = 99;

static void memcpy() {
    const char b1[] = "0123456789";
    char b2[sizeof(b1)] = {0};

    for(size_t i = 0; i < sizeof(b1); ++i) {
        memset(b2, 0, sizeof(b2));
        memcpy(b2, b1 + i, sizeof(b1) - i);
        WVASSERTSTREQ(b1 + i, b2);
    }

    {
        std::unique_ptr<char[]> buf1(new char[LARGE_BUF_SIZE]);
        std::unique_ptr<char[]> buf2(new char[LARGE_BUF_SIZE]);
        for(size_t i = 0; i < LARGE_BUF_SIZE; ++i)
            buf1[i] = i;

        memcpy(buf2.get(), buf1.get(), LARGE_BUF_SIZE);
        WVASSERTEQ(memcmp(buf1.get(), buf2.get(), LARGE_BUF_SIZE), 0);
    }
}

static void memmove() {
    {
        char buf[] = "0123456789";
        memmove(buf, buf, sizeof(buf) - 1);
        WVASSERTEQ(memcmp(buf, "0123456789", sizeof(buf) - 1), 0);
    }
    {
        char buf[] = "0123456789";
        memmove(buf + 1, buf, sizeof(buf) - 2);
        WVASSERTEQ(memcmp(buf, "0012345678", sizeof(buf) - 1), 0);
    }
    {
        char buf[] = "0123456789";
        memmove(buf + 3, buf, sizeof(buf) - 4);
        WVASSERTEQ(memcmp(buf, "0120123456", sizeof(buf) - 1), 0);
    }
    {
        char buf[] = "0123456789";
        memmove(buf, buf + 1, sizeof(buf) - 2);
        WVASSERTEQ(memcmp(buf, "1234567899", sizeof(buf) - 1), 0);
    }
    {
        char buf[] = "0123456789";
        memmove(buf, buf + 3, sizeof(buf) - 4);
        WVASSERTEQ(memcmp(buf, "3456789789", sizeof(buf) - 1), 0);
    }
    {
        std::unique_ptr<char[]> buf1(new char[LARGE_BUF_SIZE]);
        std::unique_ptr<char[]> buf2(new char[LARGE_BUF_SIZE]);
        for(size_t i = 0; i < LARGE_BUF_SIZE; ++i) {
            buf1[i] = i;
            buf2[i] = i == 0 ? 0 : i - 1;
        }

        memmove(buf1.get() + 1, buf1.get(), LARGE_BUF_SIZE - 1);
        WVASSERTEQ(memcmp(buf1.get(), buf2.get(), LARGE_BUF_SIZE), 0);
    }
}

static void memset() {
    {
        char buf[]= "0123456789";
        memset(buf + 0, 'a', sizeof(buf) - 0);
        WVASSERTEQ(memcmp(buf, "aaaaaaaaaa", sizeof(buf) - 1), 0);
    }
    {
        char buf[]= "0123456789";
        memset(buf + 1, 'a', sizeof(buf) - 1);
        WVASSERTEQ(memcmp(buf, "0aaaaaaaaa", sizeof(buf) - 1), 0);
    }
    {
        char buf[]= "0123456789";
        memset(buf + 3, 'a', sizeof(buf) - 3);
        WVASSERTEQ(memcmp(buf, "012aaaaaaa", sizeof(buf) - 1), 0);
    }
    {
        char buf[]= "0123456789";
        memset(buf + 9, 'a', sizeof(buf) - 9);
        WVASSERTEQ(memcmp(buf, "012345678a", sizeof(buf) - 1), 0);
    }
}

static void memcmp() {
    const char b1[] = "0123456789";
    char b2[] = "0123456789";

    WVASSERTEQ(memcmp(b1, b2, sizeof(b1)), 0);

    for(size_t i = 0; i < sizeof(b1); ++i) {
        b2[i] = 'a';
        WVASSERT(memcmp(b1, b2, sizeof(b1)) < 0);
        WVASSERT(memcmp(b2, b1, sizeof(b1)) > 0);
    }
}

void tstring() {
    RUN_TEST(memcpy);
    RUN_TEST(memmove);
    RUN_TEST(memset);
    RUN_TEST(memcmp);
}
