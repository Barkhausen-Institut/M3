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

#if defined(__kachel__)
#   define _GNU_SOURCE
#   include <stdlib.h>
#endif

#include <base/Common.h>

#include <m3/tiles/ChildActivity.h>
#include <m3/EnvVars.h>
#include <m3/Test.h>

#include "../unittests.h"

using namespace m3;

static void basics() {
    WVASSERTSTREQ(EnvVars::get("FOO"), nullptr);
    EnvVars::set("TEST", "value");
    WVASSERTSTREQ(EnvVars::get("TEST"), "value");

    WVASSERTEQ(EnvVars::count(), 1u);
    auto vars = EnvVars::vars();
    WVASSERTSTREQ(vars[0], "TEST=value");
    WVASSERTSTREQ(vars[1], nullptr);

    EnvVars::remove("ABC");
    WVASSERTEQ(EnvVars::count(), 1u);
    EnvVars::remove("TEST");
    WVASSERTEQ(EnvVars::count(), 0u);
    WVASSERTSTREQ(EnvVars::get("FOO"), nullptr);
}

static void multi() {
    EnvVars::set("V1", "val1");
#if defined(__kachel__)
    setenv("V2", "val2", 1);
#else
    EnvVars::set("V2", "val2");
#endif
    EnvVars::set("V2", "val3");
    EnvVars::set("V21", "val=with=eq");
    WVASSERTEQ(EnvVars::count(), 3u);

    {
        auto vars = EnvVars::vars();
        WVASSERTSTREQ(vars[0], "V1=val1");
        WVASSERTSTREQ(vars[1], "V2=val3");
        WVASSERTSTREQ(vars[2], "V21=val=with=eq");
        WVASSERTSTREQ(vars[3], nullptr);
    }

    EnvVars::remove("V1");
    WVASSERTEQ(EnvVars::count(), 2u);
    {
        auto vars = EnvVars::vars();
        WVASSERTSTREQ(vars[0], "V2=val3");
        WVASSERTSTREQ(vars[1], "V21=val=with=eq");
        WVASSERTSTREQ(vars[2], nullptr);
    }

#if defined(__kachel__)
    unsetenv("V21");
#else
    EnvVars::remove("V21");
#endif
    WVASSERTEQ(EnvVars::count(), 1u);
    {
        auto vars = EnvVars::vars();
        WVASSERTSTREQ(vars[0], "V2=val3");
        WVASSERTSTREQ(vars[1], nullptr);
    }

    EnvVars::remove("V2");
    WVASSERTEQ(EnvVars::count(), 0u);
    {
        auto vars = EnvVars::vars();
        WVASSERTSTREQ(vars[0], nullptr);
    }
}

static void to_child() {
    EnvVars::set("V1", "val1");
    EnvVars::set("V2", "val2");
    EnvVars::set("V3", "val3");

    ChildActivity act(Tile::get("clone|own"), "child");

    act.run([] {
        auto vars = EnvVars::vars();
        WVASSERTEQ(EnvVars::count(), 3u);
        WVASSERTSTREQ(vars[0], "V1=val1");
        WVASSERTSTREQ(vars[1], "V2=val2");
        WVASSERTSTREQ(vars[2], "V3=val3");
        WVASSERTSTREQ(vars[3], nullptr);
        EnvVars::remove("V2");
        WVASSERTEQ(EnvVars::count(), 2u);
        return 0;
    });

    WVASSERTEQ(act.wait(), 0);

    EnvVars::remove("V2");
    EnvVars::remove("V3");
    EnvVars::remove("V1");
    WVASSERTEQ(EnvVars::count(), 0u);
}

void tenvvars() {
    RUN_TEST(basics);
    RUN_TEST(multi);
    RUN_TEST(to_child);
}
