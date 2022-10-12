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

// ************************************************************************************************

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <algorithm>
#include <iostream>

#if defined(__m3__)

#include <m3/com/RecvGate.h>
#include <m3/com/GateStream.h>
#include <m3/stream/Standard.h>

#else

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#endif

#include "dashboard.h"
#include "errorhelper.h"

using namespace Err;

// ************************************************************************************************

class DashboadConnector {
public:
    virtual void work();

protected:
    DashboadConnector();

    virtual std::string receiveCommandFromDashboard();
    virtual void sendReportToDashboard(std::string report);
    virtual std::string receiveReportFromClient() = 0;
    virtual void sendCommandToClient(std::string command) = 0;

    int boundSocket;
    int sessionSocket;
};


DashboadConnector::DashboadConnector() {

    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(RATLS_DASHBOARD_CLIENT_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    boundSocket = chksys(socket(AF_INET, SOCK_STREAM, 0), "open dashboard socket");

#if ! defined(__m3__)
    int so_reuseaddr_enable = 1;
    chksys(setsockopt(boundSocket, SOL_SOCKET, SO_REUSEADDR, &so_reuseaddr_enable,
                      sizeof(so_reuseaddr_enable)), "setsockopt SO_REUSEADDR");
#endif

    chksys(bind(boundSocket, (struct sockaddr*)&addr, sizeof(addr)), "bind to dashboard socket");
    chksys(listen(boundSocket, 1), "listen to socket");
}


std::string DashboadConnector::receiveCommandFromDashboard() {

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    sessionSocket = chksys(accept(boundSocket, (struct sockaddr*)&addr, &addr_len),
                           "accept dashboard session");

    char commandBuf[RATLS_DASHBOARD_MESSAGE_SIZE];
    ssize_t commandSize = chksys(read(sessionSocket, commandBuf, sizeof(commandBuf)),
                                 "receive command from dashboard");

    // null-terminate command string
    commandBuf[(commandSize > 0) ? (commandSize - 1) : 0] = 0;

    return commandBuf;
}


void DashboadConnector::sendReportToDashboard(std::string report) {
    
    chksys(write(sessionSocket, report.c_str(), report.length()), "send report to dashboard");
    char const sep[] = "===\n";
    chksys(write(sessionSocket, sep, strlen(sep)), "send report seprator to dashboard");
}


void DashboadConnector::work() {

    while (true) {
        auto command = receiveCommandFromDashboard();
        printf("%s\n", command.c_str());
        sendCommandToClient(command);

        while(true) {
            auto report = receiveReportFromClient();
            if (report.length() == 0)
                break;

            printf("%s===\n", report.c_str());
            sendReportToDashboard(report);
        }
        printf("\n\n\n");

        close(sessionSocket);
    }
}


// ************************************************************************************************

#if defined(__m3__)

using namespace m3;

class M3Connector : public DashboadConnector {
public:
    M3Connector() :
        rgate(RecvGate::create_named("report")),
        sgate(SendGate::create_named("command"))
    {
        rgate.activate();
    }

    virtual void sendCommandToClient(std::string command) {
        String cmd = command.c_str();
        send_receive_vmsg(sgate, cmd);
    }

    virtual std::string receiveReportFromClient() {
        String report;
        auto is = receive_msg(rgate);
        is >> report;
        reply_vmsg(is, 0);

        return report.c_str();
    }

protected:
    RecvGate rgate;
    SendGate sgate;
};

// ************************************************************************************************

#else

// ************************************************************************************************

class UnixPipeConnector : public DashboadConnector {
public:
    UnixPipeConnector() {
        commandPipeFd = chksys(open(RATLS_DASHBOARD_CONNECTOR_COMMAND_FIFO, O_WRONLY),
                               "open dashboard command fifo");
        reportPipeFd = chksys(open(RATLS_DASHBOARD_CONNECTOR_REPORT_FIFO, O_RDONLY),
                              "open dashboard report fifo");
    }

    virtual void sendCommandToClient(std::string command) {
        size_t commandSize = command.length() + 1; // length + null byte
        chksys(write(commandPipeFd, &commandSize, sizeof(commandSize)), "write command size");
        chksys(write(commandPipeFd, command.c_str(), commandSize), "write command");
    }

    virtual std::string receiveReportFromClient() {
        size_t reportSize;
        char reportBuf[RATLS_DASHBOARD_MESSAGE_SIZE];
        
        chksys(read(reportPipeFd, &reportSize, sizeof(reportSize)), "read report size");
        reportSize = std::min(reportSize, sizeof(reportBuf));

        chksys(read(reportPipeFd, reportBuf, reportSize), "read report");
        reportBuf[reportSize-1] = 0;
    
        return std::string(reportBuf);
    }

protected:
    int commandPipeFd;
    int reportPipeFd;
};

#endif

// ************************************************************************************************

int main() {

    setlinebuf(stdout);

    try {
#if defined(__m3__)
        M3Connector connector;
#else
        UnixPipeConnector connector;
#endif

        connector.work();
    }

    catch (const std::runtime_error& exc) {
        std::cerr << "ratls-dashboard: " << exc.what() << "\nExiting...\n";
        return 1;
    }

    return 0;
}
