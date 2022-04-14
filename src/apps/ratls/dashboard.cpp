/*
 * Copyright (C) 2015-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <m3/com/RecvGate.h>
#include <m3/com/GateStream.h>
#include <m3/stream/Standard.h>
#include <m3/session/VTerm.h>

using namespace m3;

int main() {
    RecvGate rgate = RecvGate::create_named("report");
    rgate.activate();
    SendGate sgate = SendGate::create_named("command");

    VTerm *vterm;
    try {
        vterm = new VTerm("vterm");

        // change stdin, stdout, and stderr to vterm
        const fd_t fds[] = {STDIN_FD, STDOUT_FD, STDERR_FD};
        for(fd_t fd : fds)
            Activity::own().files()->set(fd, vterm->create_channel(fd == STDIN_FD));
    }
    catch(const Exception &e) {
        errmsg("Unable to open vterm: " << e.what());
    }

    while(1) {
        cout << "Enter command: ";
        cout.flush();

        String cmd;
        cin >> cmd;
        cout << "Received command '" << cmd << "'\n";
        send_receive_vmsg(sgate, 0);

        while(true) {
            String report;
            auto is = receive_msg(rgate);
            is >> report;
            reply_vmsg(is, 0);
            if(report.length() == 0)
                break;
            cout << "RECEIVED REPORT\n" << report << "\n\n";
        }
    }
    return 0;
}
