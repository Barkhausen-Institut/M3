/*
 * Copyright (C) 2015-2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <m3/com/GateStream.h>
#include <m3/server/SimpleRequestHandler.h>
#include <m3/server/Server.h>

using namespace m3;

enum TestOp {
    TEST
};

class TestRequestHandler;
using base_class = SimpleRequestHandler<TestRequestHandler, TestOp, 1>;

static Server<TestRequestHandler> *srv;

class TestRequestHandler : public base_class {
public:
    explicit TestRequestHandler(WorkLoop *wl) : base_class(wl) {
        add_operation(TEST, &TestRequestHandler::test);
    }

    void test(GateIStream &is) {
        String str;
        is >> str;
        char *resp = new char[str.length() + 1];
        for(size_t i = 0; i < str.length(); ++i)
            resp[str.length() - i - 1] = str[i];
        reply_vmsg(is, String(resp, str.length()));
        delete[] resp;

        // pretend that we crash after some requests
        static int count = 0;
        if(++count == 6)
            srv->shutdown();
    }
};

int main() {
    WorkLoop wl;

    srv = new Server<TestRequestHandler>("testmsgs", &wl, new TestRequestHandler(&wl));

    wl.run();

    delete srv;
    return 0;
}
