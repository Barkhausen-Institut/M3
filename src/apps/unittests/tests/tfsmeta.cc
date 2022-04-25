/*
 * Copyright (C) 2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019-2021 Nils Asmussen, Barkhausen Institut
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

#include <base/stream/IStringStream.h>

#include <m3/stream/FStream.h>
#include <m3/vfs/Dir.h>
#include <m3/vfs/FileRef.h>
#include <m3/vfs/VFS.h>
#include <m3/Test.h>

#include <algorithm>
#include <vector>

#include "../unittests.h"

using namespace m3;

template<typename F>
static void test_path(F func, const char *in, const char *out) {
    char dst[256];
    size_t len = func(dst, sizeof(dst), in);
    WVASSERTEQ(len, strlen(out));
    WVASSERTSTREQ(dst, out);
}

static void paths() {
    test_path(VFS::canon_path, "", "");
    test_path(VFS::canon_path, ".", "");
    test_path(VFS::canon_path, "..", "");
    test_path(VFS::canon_path, ".//foo/bar", "foo/bar");
    test_path(VFS::canon_path, "./foo/..///bar", "bar");
    test_path(VFS::canon_path, "..//.//..//foo/../bar/..", "");
    test_path(VFS::canon_path, "../.test//foo/..///", ".test");
    test_path(VFS::canon_path, "/foo/..//bar", "/bar");

    WVASSERTERR(Errors::NO_SUCH_FILE, [] { VFS::set_cwd("/non-existing-dir"); });
    WVASSERTERR(Errors::IS_NO_DIR, [] { VFS::set_cwd("/test.txt"); });
    VFS::set_cwd(".././bin/./.");
    WVASSERTSTREQ(VFS::cwd(), "/bin");

    test_path(VFS::abs_path, "", "/bin");
    test_path(VFS::abs_path, ".", "/bin");
    test_path(VFS::abs_path, "..", "/bin");
    test_path(VFS::abs_path, ".//foo/bar", "/bin/foo/bar");
    test_path(VFS::abs_path, "./foo/..///bar", "/bin/bar");
    test_path(VFS::abs_path, "..//.//..//foo/../bar/..", "/bin");
    test_path(VFS::abs_path, "../.test//foo/..///", "/bin/.test");

    VFS::set_cwd("/");
}

static void dir_listing() {
    // read a dir with known content
    const char *dirname = "/largedir";
    Dir dir(dirname);

    Dir::Entry e;
    std::vector<Dir::Entry> entries;
    while(dir.readdir(e))
        entries.push_back(e);
    WVASSERTEQ(entries.size(), 82u);

    // we don't know the order because it is determined by the host OS. thus, sort it first.
    std::sort(entries.begin(), entries.end(), [] (const Dir::Entry &a, const Dir::Entry &b) -> bool {
        bool aspec = strcmp(a.name, ".") == 0 || strcmp(a.name, "..") == 0;
        bool bspec = strcmp(b.name, ".") == 0 || strcmp(b.name, "..") == 0;
        if(aspec && bspec)
            return strcmp(a.name, b.name) < 0;
        if(aspec)
            return true;
        if(bspec)
            return false;
        return IStringStream::read_from<int>(a.name) < IStringStream::read_from<int>(b.name);
    });

    // now check file names
    WVASSERTEQ(entries[0].name, StringRef("."));
    WVASSERTEQ(entries[1].name, StringRef(".."));
    for(size_t i = 0; i < 80; ++i) {
        char tmp[16];
        OStringStream os(tmp, sizeof(tmp));
        os << i << ".txt";
        WVASSERTEQ(entries[i + 2].name, StringRef(os.str()));
    }
}

static void meta_operations() {
    VFS::mkdir("/example", 0755);
    WVASSERTERR(Errors::EXISTS, [] { VFS::mkdir("/example", 0755); });
    WVASSERTERR(Errors::NO_SUCH_FILE, [] { VFS::mkdir("/example/foo/bar", 0755); });

    FileInfo info;
    VFS::stat("/example", info);
    WVASSERT(M3FS_ISDIR(info.mode));
    WVASSERTERR(Errors::NO_SUCH_FILE, [&info] { VFS::stat("/example/foo", info); });

    {
        FStream f("/example/myfile", FILE_W | FILE_CREATE);
        f << "test\n";
    }

    WVASSERTERR(Errors::INV_ARGS, [] { VFS::mount("/mnt", "unknownfs", "session"); });
    WVASSERTERR(Errors::EXISTS, [] { VFS::mount("/", "m3fs", "m3fs-clone"); });

    try {
        VFS::mount("/fs/", "m3fs", "m3fs-clone");
        WVASSERTERR(Errors::XFS_LINK, [] { VFS::link("/example/myfile", "/fs/foo"); });
        WVASSERTERR(Errors::XFS_LINK, [] { VFS::rename("/fs/example/myfile", "/example/myfile2"); });
        VFS::unmount("/fs");
    }
    catch(const Exception &e) {
        cerr << "Mount test failed: " << e.what() << "\n";
    }

    WVASSERTERR(Errors::NO_SUCH_FILE, [] { VFS::rmdir("/example/foo/bar"); });
    WVASSERTERR(Errors::IS_NO_DIR, [] { VFS::rmdir("/example/myfile"); });
    WVASSERTERR(Errors::DIR_NOT_EMPTY, [] { VFS::rmdir("/example"); });

    WVASSERTERR(Errors::IS_DIR, [] { VFS::link("/example", "/newpath"); });
    WVASSERTERR(Errors::NO_SUCH_FILE, [] { VFS::link("/example/myfile", "/foo/bar"); });
    VFS::link("/example/myfile", "/newpath");

    WVASSERTERR(Errors::NO_SUCH_FILE, [] { VFS::rename("/example/myfile", "/foo/bar"); });
    WVASSERTERR(Errors::NO_SUCH_FILE, [] { VFS::rename("/foo/bar", "/example/myfile"); });
    VFS::rename("/example/myfile", "/example/myfile2");

    WVASSERTERR(Errors::IS_DIR, [] { VFS::unlink("/example"); });
    WVASSERTERR(Errors::NO_SUCH_FILE, [] { VFS::unlink("/example/foo"); });
    VFS::unlink("/example/myfile2");

    VFS::rmdir("/example");
    VFS::unlink("/newpath");
}

static void delete_file() {
    const char *tmp_file = "/tmp_file.txt";

    {
        FStream f(tmp_file, FILE_W | FILE_CREATE);
        f << "test\n";
    }

    {
        char buffer[32];

        auto file = VFS::open(tmp_file, FILE_R);

        VFS::unlink(tmp_file);

        WVASSERTERR(Errors::NO_SUCH_FILE, [&tmp_file] { VFS::open(tmp_file, FILE_R); });

        WVASSERTEQ(file->read(buffer, sizeof(buffer)), 5);
    }

    WVASSERTERR(Errors::NO_SUCH_FILE, [&tmp_file] { VFS::open(tmp_file, FILE_R); });
}

static void relative_paths() {
    VFS::set_cwd("/");

    VFS::mkdir("example", 0755);
    WVASSERTERR(Errors::EXISTS, [] { VFS::mkdir("example", 0755); });
    WVASSERTERR(Errors::NO_SUCH_FILE, [] { VFS::mkdir("example/foo/bar", 0755); });

    FileInfo info;
    VFS::stat("example", info);
    WVASSERT(M3FS_ISDIR(info.mode));
    WVASSERTERR(Errors::NO_SUCH_FILE, [&info] { VFS::stat("example/foo", info); });

    {
        FStream f("./../example/myfile", FILE_W | FILE_CREATE);
        f << "test\n";
    }

    WVASSERTERR(Errors::NO_SUCH_FILE, [] { VFS::rmdir("example/foo/bar"); });
    WVASSERTERR(Errors::IS_NO_DIR, [] { VFS::rmdir("example/myfile"); });
    WVASSERTERR(Errors::DIR_NOT_EMPTY, [] { VFS::rmdir("example"); });

    WVASSERTERR(Errors::IS_DIR, [] { VFS::link("example", "newpath"); });
    VFS::link("example/myfile", "./newpath");
    VFS::rename("example/myfile", "example/myfile2");

    WVASSERTERR(Errors::IS_DIR, [] { VFS::unlink("example"); });
    WVASSERTERR(Errors::NO_SUCH_FILE, [] { VFS::unlink("example/foo"); });
    VFS::unlink("./example/myfile2");

    VFS::rmdir("example");
    VFS::unlink("newpath");

    VFS::set_cwd(nullptr);
}

void tfsmeta() {
    RUN_TEST(paths);
    RUN_TEST(dir_listing);
    RUN_TEST(meta_operations);
    RUN_TEST(delete_file);
    RUN_TEST(relative_paths);
}
