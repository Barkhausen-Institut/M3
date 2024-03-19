/*
 * Copyright (C) 2022 Nils Asmussen, Barkhausen Institut
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
#include <m3/pipe/IndirectPipe.h>
#include <m3/tiles/ChildActivity.h>
#include <m3/vfs/VFS.h>

#include "../libctest.h"

using namespace m3;

constexpr size_t PIPE_SIZE = 512 * 1024;

static void run_command(int argc, const char *const *argv, const char *expected) {
    Pipes pipes("pipes");
    MemCap mem = MemCap::create_global(PIPE_SIZE, MemCap::RW);
    IndirectPipe pipe(pipes, mem, PIPE_SIZE);

    auto tile = Tile::get("compat|own");
    ChildActivity child(tile, "child");
    child.add_file(STDIN_FD, STDIN_FD);
    child.add_file(STDOUT_FD, pipe.writer().fd());
    child.add_file(STDERR_FD, STDERR_FD);
    child.add_mount("/", "/");

    child.exec(argc, argv);

    pipe.close_writer();

    {
        OStringStream os;
        FStream f(pipe.reader().fd(), FILE_R);
        while(true) {
            char c = f.read();
            if(f.bad())
                break;
            os.write(c);
        }
        WVASSERTSTREQ(os.str(), expected);
    }

    pipe.close_reader();

    WVASSERTEQ(child.wait(), 0);
}

static void bsd_cat() {
    const char *expected = "This is a test\n";
    const char *argv[] = {"/bin/cat", "/test.txt", nullptr};
    run_command(ARRAY_SIZE(argv) - 1, argv, expected);
}

static void bsd_du() {
    const char *expected = "1.5K\t/subdir\n";
    const char *argv[] = {"/bin/du", "-sh", "/subdir", nullptr};
    run_command(ARRAY_SIZE(argv) - 1, argv, expected);
}

static void bsd_find() {
    const char *expected = "/largedir/12.txt\n";
    const char *argv[] = {"/bin/find", "/largedir", "-name", "12.txt", nullptr};
    run_command(ARRAY_SIZE(argv) - 1, argv, expected);
}

static void bsd_head() {
    const char *expected =
        "104 104 992\n"
        "1 1  4.5988460064935e-01\n"
        "2 1  3.6284044982049e-02\n"
        "5 1  1.0781816562027e+00\n"
        "6 1  2.8797109621776e-02\n"
        "55 1 -8.6315697399926e-03\n"
        "56 1  1.0598980317711e-04\n"
        "1 2  1.8698118212961e-01\n"
        "2 2  4.7481454523109e+00\n"
        "5 2  2.2001171666844e-02\n";
    const char *argv[] = {"/bin/head", "/mat.txt", nullptr};
    run_command(ARRAY_SIZE(argv) - 1, argv, expected);
}

static void bsd_ls() {
    const char *expected = ".\n..\nsubsubdir\n";
    const char *argv[] = {"/bin/ls", "-a", "/subdir", nullptr};
    run_command(ARRAY_SIZE(argv) - 1, argv, expected);
}

static void bsd_printenv() {
    // in case LOG has been set, save&unset it before the test
    char *log = getenv("LOG");
    std::string logcpy(log ? log : "");
    if(log)
        unsetenv("LOG");

    VFS::set_cwd("/bin");
    const char *expected = "PWD=/bin\n";
    const char *argv[] = {"/bin/printenv", nullptr};
    run_command(ARRAY_SIZE(argv) - 1, argv, expected);
    VFS::set_cwd("/");

    // restore LOG if it was set
    if(log)
        setenv("LOG", logcpy.c_str(), 1);
}

static void bsd_stat() {
    const char *expected =
        "  File: \"/subdir\"\n"
        "  Size: 4096         FileType: Directory\n"
        "  Mode: (0755/drwxr-xr-x)         Uid: (    0/     (0))  Gid: (    0/     (0))\n"
        "Device: 0,0   Links: 3\n";
    const char *fmt =
        "  File: \"%N\"%n"
        "  Size: %-11z  FileType: %HT%n"
        "  Mode: (%01Mp%03OLp/%.10Sp)         Uid: (%5u/%8Su)  Gid: (%5g/%8Sg)%n"
        "Device: %Hd,%Ld   Links: %l%n";
    const char *argv[] = {"/bin/stat", "-f", fmt, "/subdir", nullptr};
    run_command(ARRAY_SIZE(argv) - 1, argv, expected);
}

static void bsd_tail() {
    const char *expected =
        "99 103  2.2126620916555e-01\n"
        "100 103 -1.6244167038031e-04\n"
        "103 103  2.4780916858431e-01\n"
        "104 103 -1.6484674443996e-04\n"
        "49 104 -1.6154510171511e-10\n"
        "50 104 -1.7166807862270e-06\n"
        "99 104  1.6247727291072e-04\n"
        "100 104  2.2259069059038e-01\n"
        "103 104  1.6485396337561e-04\n"
        "104 104  2.4916205005771e-01";
    const char *argv[] = {"/bin/tail", "/mat.txt", nullptr};
    run_command(ARRAY_SIZE(argv) - 1, argv, expected);
}

static void bsd_wc() {
    const char *expected = "     992    2979   26715 /mat.txt\n";
    const char *argv[] = {"/bin/wc", "/mat.txt", nullptr};
    run_command(ARRAY_SIZE(argv) - 1, argv, expected);
}

void tbsdutils() {
    RUN_TEST(bsd_cat);
    RUN_TEST(bsd_du);
    RUN_TEST(bsd_find);
    RUN_TEST(bsd_head);
    RUN_TEST(bsd_ls);
    RUN_TEST(bsd_printenv);
    RUN_TEST(bsd_stat);
    RUN_TEST(bsd_tail);
    RUN_TEST(bsd_wc);
}
