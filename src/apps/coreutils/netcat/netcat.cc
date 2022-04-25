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

#include <base/stream/IStringStream.h>
#include <base/CmdArgs.h>

#include <m3/net/DNS.h>
#include <m3/net/TcpSocket.h>
#include <m3/net/UdpSocket.h>
#include <m3/session/NetworkManager.h>
#include <m3/stream/Standard.h>
#include <m3/vfs/Waiter.h>

using namespace m3;

struct Buffer {
    explicit Buffer(size_t len) : buf(new char[len]()), pos(), total() {
    }

    size_t left() const {
        return total - pos;
    }
    void push(ssize_t amount) {
        if(amount > 0) {
            total = static_cast<size_t>(amount);
            pos = 0;
        }
    }
    void pop(ssize_t amount) {
        if(amount > 0)
            pos += static_cast<size_t>(amount);
        if(pos == total)
            pos = total = 0;
    }

    std::unique_ptr<char[]> buf;
    size_t pos;
    size_t total;
};

constexpr size_t INBUF_SIZE = 1024;
constexpr size_t OUTBUF_SIZE = 1024;

static void set_nonblocking(File *file) {
    try {
        file->set_blocking(false);
    }
    catch(...) {
        // ignore it; files without non-blocking support will always immediatly provide a response
    }
}

static FileRef<Socket> connect(NetworkManager &net, const IpAddr &ip, port_t port, bool tcp) {
    if(tcp) {
        auto socket = TcpSocket::create(net);
        socket->connect(Endpoint(ip, port));
        return socket;
    }

    auto socket = UdpSocket::create(net);
    socket->connect(Endpoint(ip, port));
    return socket;
}

static void usage(const char *name) {
    cerr << "Usage: " << name << " [-t] [-u] [-v] <ip> <port>\n";
    exit(1);
}

int main(int argc, char **argv) {
    bool tcp     = true;
    bool verbose = false;

    int opt;
    while((opt = CmdArgs::get(argc, argv, "vtu")) != -1) {
        switch(opt) {
            case 'v': verbose = true; break;
            case 't': tcp = true; break;
            case 'u': tcp = false; break;
            default:
                usage(argv[0]);
        }
    }
    if(CmdArgs::is_help(argc, argv) || CmdArgs::ind + 1 >= argc)
        usage(argv[0]);

    const char *dest_str = argv[CmdArgs::ind + 0];
    const char *port_str = argv[CmdArgs::ind + 1];

    NetworkManager net("net");

    DNS dns;
    IpAddr dest = dns.get_addr(net, dest_str);
    int port    = IStringStream::read_from<port_t>(port_str);

    auto socket = connect(net, dest, port, tcp);

    // make all files non-blocking to work with all simultaneously
    set_nonblocking(&*socket);
    set_nonblocking(cin.file());
    set_nonblocking(cout.file());

    FileWaiter waiter;
    waiter.add(socket->fd(), File::INPUT);
    waiter.add(cin.file()->fd(), File::INPUT);

    Buffer input(INBUF_SIZE);
    Buffer output(OUTBUF_SIZE);
    bool eof = false;
    while(true) {
        // if we don't have input, try to get some
        if(!eof && input.pos == 0) {
            // reset state in case we got a would-block error earlier
            cin.clear_state();
            size_t read = cin.getline(input.buf.get(), INBUF_SIZE - 1);

            // if we received EOF, simply stop reading and waiting for stdin from now on
            eof = cin.eof();
            if(eof)
                waiter.remove(cin.file()->fd());
            // getline doesn't include the newline character
            else if(cin.good())
                input.buf[read++] = '\n';
            if(verbose) {
                if(eof)
                    cerr << "-- read EOF from stdin\n";
                else
                    cerr << "-- read " << read << "b from stdin\n";
            }

            input.push(static_cast<ssize_t>(read));
        }

        // if we have input, try to send it
        if(input.left() > 0) {
            ssize_t sent = socket->send(input.buf.get() + input.pos, input.left());
            if(verbose)
                cerr << "-- send " << sent << "b to " << socket->remote_endpoint() << "\n";
            input.pop(sent);
        }

        // if we can receive data, do it
        if(socket->has_data()) {
            ssize_t recv = socket->recv(output.buf.get(), OUTBUF_SIZE);
            if(verbose)
                cerr << "-- received " << recv << "b from " << socket->remote_endpoint() << "\n";
            output.push(recv);
        }
        // if we have received data, try to output it
        if(output.left() > 0) {
            cout.clear_state();
            ssize_t written = cout.write(output.buf.get() + output.pos, output.left());
            if(verbose)
                cerr << "-- wrote " << written << "b to stdout\n";
            output.pop(written);
            cout.flush();

            if(output.left() > 0)
                waiter.set(cout.file()->fd(), File::OUTPUT);
            else
                waiter.remove(cout.file()->fd());
        }

        // continue if the socket is connected, there is data left to receive or data left to write
        if((!tcp || socket->state() == Socket::Connected) || socket->has_data() || output.left() > 0)
            waiter.wait();
        else
            break;
    }
    return 0;
}
