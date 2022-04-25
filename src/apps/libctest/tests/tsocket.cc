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

#include <m3/com/Semaphore.h>
#include <m3/tiles/ChildActivity.h>
#include <m3/Test.h>

#define _GNU_SOURCE // for NI_MAXSERV
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "../libctest.h"

using namespace m3;

EXTERN_C int __m3_init_netmng(const char *name);

constexpr size_t BUF_SIZE = 256;

static int open_socket(const char *addr, const char *port, int type, struct addrinfo **rp) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = type;
    hints.ai_flags    = 0;
    hints.ai_protocol = 0;

    struct addrinfo *result;
    WVASSERTEQ(getaddrinfo(addr, port, &hints, &result), 0);

    int sfd;
    for(*rp = result; *rp != NULL; *rp = (*rp)->ai_next) {
        sfd = socket((*rp)->ai_family, (*rp)->ai_socktype, (*rp)->ai_protocol);
        if(sfd == -1)
            continue;
        if(connect(sfd, (*rp)->ai_addr, (*rp)->ai_addrlen) != -1)
            break;
        close(sfd);
    }

    freeaddrinfo(result);
    WVASSERT(*rp != NULL);
    return sfd;
}

static void generic_echo(const char *addr, const char *port, int type) {
    struct addrinfo *rp;
    int sfd = open_socket(addr, port, type, &rp);

    struct sockaddr_in local, remote;
    socklen_t local_len = sizeof(local), remote_len = sizeof(remote);

    WVASSERTEQ(getsockname(sfd, (struct sockaddr *)&local, &local_len), 0);
    WVASSERTEQ(sizeof(local), local_len);
    WVASSERTSTREQ(inet_ntoa(local.sin_addr), "127.0.0.1");

    WVASSERTEQ(getpeername(sfd, (struct sockaddr *)&remote, &remote_len), 0);
    WVASSERTEQ(sizeof(remote), remote_len);
    WVASSERTSTREQ(inet_ntoa(remote.sin_addr), "127.0.0.1");
    WVASSERTEQ(remote.sin_port, atoi(port));

    char buf[BUF_SIZE];

    WVASSERTEQ(write(sfd, "test", 4), 4);
    WVASSERTEQ(read(sfd, buf, BUF_SIZE), 4);
    WVASSERT(strncmp(buf, "test", 4) == 0);

    WVASSERTEQ(send(sfd, "foobar", 6, 0), 6);
    WVASSERTEQ(recv(sfd, buf, BUF_SIZE, 0), 6);
    WVASSERT(strncmp(buf, "foobar", 6) == 0);

    struct sockaddr_in src;
    socklen_t src_len = sizeof(src);
    WVASSERTEQ(sendto(sfd, "zombie", 6, 0, rp->ai_addr, rp->ai_addrlen), 6);
    WVASSERTEQ(recvfrom(sfd, buf, BUF_SIZE, 0, (struct sockaddr *)&src, &src_len), 6);
    WVASSERTEQ(sizeof(src), src_len);
    WVASSERTSTREQ(inet_ntoa(src.sin_addr), "127.0.0.1");
    WVASSERTEQ(src.sin_port, atoi(port));
    WVASSERT(strncmp(buf, "zombie", 6) == 0);

    struct iovec msg_data;
    msg_data.iov_base = (void *)"mytest";
    msg_data.iov_len  = 6;
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov    = &msg_data;
    msg.msg_iovlen = 1;
    WVASSERTEQ(sendmsg(sfd, &msg, 0), 6);

    msg_data.iov_base = buf;
    msg_data.iov_len  = sizeof(buf);
    WVASSERTEQ(recvmsg(sfd, &msg, 0), 6);
    WVASSERT(strncmp(buf, "mytest", 6) == 0);

    WVASSERTEQ(shutdown(sfd, SHUT_RDWR), 0);

    close(sfd);
}

static void udp_echo() {
    generic_echo("127.0.0.1", "1337", SOCK_DGRAM);
}

static void tcp_echo() {
    Semaphore::attach("net-tcp").down();
    generic_echo("127.0.0.1", "1338", SOCK_STREAM);
}

static int tcp_server() {
    // connect to netmng explicitly here to specify a different session name
    __m3_init_netmng("netserv");

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family    = AF_INET;
    hints.ai_socktype  = SOCK_STREAM;
    hints.ai_flags     = AI_PASSIVE;
    hints.ai_protocol  = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr      = NULL;
    hints.ai_next      = NULL;

    struct addrinfo *result;
    WVASSERTEQ(getaddrinfo(NULL, "2000", &hints, &result), 0);

    int sfd;
    struct addrinfo *rp;
    for(rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(sfd == -1)
            continue;
        if(bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(sfd);
    }

    freeaddrinfo(result);
    WVASSERT(rp != nullptr);

    WVASSERTEQ(listen(sfd, 1), 0);

    struct sockaddr_in peer_addr;
    socklen_t peer_addr_size = sizeof(peer_addr);
    int cfd = accept4(sfd, (struct sockaddr *)&peer_addr, &peer_addr_size, 0);
    WVASSERT(cfd != -1);

    char buf[BUF_SIZE];
    peer_addr_size = sizeof(peer_addr);
    ssize_t nread = recvfrom(cfd, buf, sizeof(buf), 0, (struct sockaddr *)&peer_addr, &peer_addr_size);
    WVASSERT(nread > 0);

    WVASSERTEQ(nread, 4);
    WVASSERTSTREQ(inet_ntoa(peer_addr.sin_addr), "127.0.0.1");

    WVASSERTEQ(send(cfd, buf, static_cast<size_t>(nread), 0), nread);

    close(cfd);
    close(sfd);

    return 0;
}

static void tcp_accept() {
    Semaphore::attach("net-tcp").down();

    auto tile = Tile::get("clone|own");
    ChildActivity server(tile, "server");
    server.run(tcp_server);

    Activity::sleep_for(TimeDuration::from_millis(10));

    struct addrinfo *rp;
    int fd = open_socket("127.0.0.1", "2000", SOCK_STREAM, &rp);

    char buf[4];
    WVASSERTEQ(send(fd, "test", 4, 0), 4);
    WVASSERTEQ(recv(fd, buf, sizeof(buf), 0), 4);
    WVASSERT(strncmp(buf, "test", 4) == 0);
    close(fd);

    WVASSERTEQ(server.wait(), 0);
}

void tsocket() {
    // wait for UDP socket just once
    Semaphore::attach("net-udp").down();

    RUN_TEST(udp_echo);
    RUN_TEST(tcp_echo);
    RUN_TEST(tcp_accept);
}
