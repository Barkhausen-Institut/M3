/*
 * Copyright (C) 2021 Nils Asmussen, Barkhausen Institut
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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "../libctest.h"

using namespace m3;

static const char TEST_CONTENT[] = "This is a test\n";
static const char TEST_CONTENT_TWICE[] = "This is a test\nThis is a test\n";

static void basics() {
    char buf[128];

    constexpr size_t TEST_LEN = sizeof(TEST_CONTENT) - 1;
    constexpr size_t TEST_TWICE_LEN = sizeof(TEST_CONTENT_TWICE) - 1;

    {
        int fd = open("/test.txt", O_RDONLY);
        WVASSERT(fd >= 0);
        WVASSERTECODE(EPERM, write(fd, nullptr, 0));
        WVASSERTEQ(read(fd, nullptr, 0), 0);
        close(fd);
    }

    {
        int fd = open("/test.txt", O_WRONLY);
        WVASSERT(fd >= 0);
        WVASSERTECODE(EPERM, read(fd, nullptr, 0));
        WVASSERTEQ(write(fd, nullptr, 0), 0);
        close(fd);
    }

    {
        int fd = open("/test.txt", O_RDWR);
        WVASSERT(fd >= 0);
        WVASSERTEQ(read(fd, nullptr, 0), 0);
        WVASSERTEQ(write(fd, nullptr, 0), 0);
        close(fd);
    }

    {
        int fd = open("/test.txt", O_RDWR | O_APPEND);
        WVASSERT(fd >= 0);
        WVASSERTEQ(write(fd, TEST_CONTENT, TEST_LEN), static_cast<ssize_t>(TEST_LEN));
        WVASSERTEQ(lseek(fd, 0, SEEK_SET), 0);
        WVASSERTEQ(read(fd, buf, sizeof(buf)), static_cast<ssize_t>(TEST_TWICE_LEN));
        buf[TEST_TWICE_LEN] = '\0';
        WVASSERTSTREQ(buf, TEST_CONTENT_TWICE);
        close(fd);
    }

    {
        int fd = open("/test.txt", O_RDWR | O_TRUNC);
        WVASSERT(fd >= 0);
        WVASSERTEQ(write(fd, TEST_CONTENT, TEST_LEN), static_cast<ssize_t>(TEST_LEN));
        WVASSERTEQ(lseek(fd, 0, SEEK_SET), 0);
        WVASSERTEQ(read(fd, buf, sizeof(buf)), static_cast<ssize_t>(TEST_LEN));
        buf[TEST_LEN] = '\0';
        WVASSERTSTREQ(buf, TEST_CONTENT);
        close(fd);
    }

    {
        int fd = open("/tmp/test.txt", O_WRONLY | O_CREAT);
        WVASSERT(fd >= 0);
        close(fd);
        fd = open("/tmp/test.txt", O_RDONLY);
        WVASSERT(fd >= 0);
        close(fd);
        WVASSERTEQ(unlink("/tmp/test.txt"), 0);
    }
}

static void misc() {
    {
        int fd = open("/test.txt", O_RDWR);
        WVASSERT(fd >= 0);
        WVASSERTEQ(fcntl(fd, F_SETLK), 0);
        WVASSERTEQ(fsync(fd), 0);
        close(fd);
    }

    WVASSERTEQ(access("/test.txt", F_OK), 0);
    WVASSERTEQ(access("/test.txt", R_OK | W_OK), 0);
    WVASSERTECODE(ENOENT, access("/tmp/non-existing", F_OK));
}

void tfile() {
    RUN_TEST(basics);
    RUN_TEST(misc);
}
