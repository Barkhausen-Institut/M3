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

#include <m3/stream/FStream.h>
#include <m3/stream/Standard.h>
#include <m3/vfs/VFS.h>

#include <errno.h>
#include <unistd.h>

#include "Builtin.h"

using namespace m3;

static int execute_cd(char **args, int);
static int execute_echo(char **args, int outfd);

Builtin::Command Builtin::commands[] = {
    {"cd", execute_cd},
    {"echo", execute_echo},
    {nullptr, nullptr},
};

bool Builtin::is_builtin(const char *name) {
    for(size_t i = 0; commands[i].name != nullptr; ++i) {
        if(strcmp(name, commands[i].name) == 0)
            return true;
    }
    return false;
}

static int execute_cd(char **args, int) {
    if(!args[1]) {
        cerr << "Usage: " << args[0] << " <path>\n";
        return 1;
    }

    try {
        VFS::set_cwd(args[1]);
    }
    catch(const Exception &e) {
        cerr << "Unable to change directory to '" << args[1] << "': " << e.what() << "\n";
        return 1;
    }
    return 0;
}

static int execute_echo(char **args, int outfd) {
    try {
        FStream fout(outfd);
        args++; // skip name
        while(*args != nullptr) {
            fout.write_all(*args, strlen(*args));
            if(*++args != nullptr)
                fout.write(' ');
        }
        fout.write('\n');
    }
    catch(const Exception &e) {
        cerr << "echo failed: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

int Builtin::execute(char **args, int outfd) {
    for(size_t i = 0; commands[i].name != nullptr; ++i) {
        if(strcmp(args[0], commands[i].name) == 0)
            return commands[i].func(args, outfd);
    }
    return 1;
}
