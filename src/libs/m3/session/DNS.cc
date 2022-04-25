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
#include <base/stream/IStringStream.h>
#include <base/util/Random.h>

#include <m3/net/DNS.h>
#include <m3/net/UdpSocket.h>
#include <m3/session/NetworkManager.h>
#include <m3/vfs/Waiter.h>

#include <endian.h>

namespace m3 {

/* based on http://tools.ietf.org/html/rfc1035 */

constexpr uint16_t DNS_RECURSION_DESIRED = 0x100;
constexpr port_t DNS_PORT                = 53;

enum Type {
    TYPE_A      = 1,    /* a host address */
    TYPE_NS     = 2,    /* an authoritative name server */
    TYPE_CNAME  = 5,    /* the canonical name for an alias */
    TYPE_HINFO  = 13,   /* host information */
    TYPE_MX     = 15,   /* mail exchange */
};

enum Class {
    CLASS_IN    = 1     /* the Internet */
};

struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdCount;
    uint16_t anCount;
    uint16_t nsCount;
    uint16_t arCount;
} A_PACKED;

struct DNSQuestionEnd {
    uint16_t type;
    uint16_t cls;
} PACKED;

struct DNSAnswer {
    uint16_t name;
    uint16_t type;
    uint16_t cls;
    uint32_t ttl;
    uint16_t length;
} PACKED;

IpAddr DNS::get_addr(NetworkManager &netmng, const char *name, TimeDuration timeout) {
    if(is_ip_addr(name)) {
        IpAddr addr;
        IStringStream is(name);
        is >> addr;
        return addr;
    }

    return resolve(netmng, name, timeout);
}

bool DNS::is_ip_addr(const char *name) {
    int dots = 0;
    int len = 0;
    // ignore whitespace at the beginning
    while(Chars::isspace(*name))
        name++;

    while(dots < 4 && len < 4 && *name) {
        if(*name == '.') {
            dots++;
            len = 0;
        }
        else if(Chars::isdigit(*name))
            len++;
        else
            break;
        name++;
    }

    // ignore whitespace at the end
    while(Chars::isspace(*name))
        name++;
    return dots == 3 && len > 0 && len < 4;
}

static void convert_hostname(char *dst, const char *src, size_t len) {
    // leave one byte space for the length of the first part
    const char *from = src + len++;
    char *to = dst + len;
    // we start with the \0 at the end
    int partLen = -1;

    for(size_t i = 0; i < len; i++, to--, from--) {
        if(*from == '.') {
            *to = partLen;
            partLen = 0;
        }
        else {
            *to = *from;
            partLen++;
        }
    }
    *to = partLen;
}

static size_t question_length(const uint8_t *data) {
    size_t total = 0;
    while(*data != 0) {
        uint8_t len = *data;
        // skip this name-part
        total += len + 1;
        data += len + 1;
    }
    // skip zero ending, too
    return total + 1;
}

IpAddr DNS::resolve(NetworkManager &netmng, const char *name, TimeDuration timeout) {
    uint8_t buffer[512];
    if(_nameserver.addr() == 0)
        _nameserver = netmng.get_nameserver();

    size_t nameLen = strlen(name);
    size_t total = sizeof(DNSHeader) + nameLen + 2 + sizeof(DNSQuestionEnd);
    if(total > sizeof(buffer))
        VTHROW(Errors::INV_ARGS, "Hostname too long");

    // generate a unique transaction id
    uint16_t txid = _rng.get();

    // build DNS request message
    DNSHeader *h = reinterpret_cast<DNSHeader*>(buffer);
    h->id = htobe16(txid);
    h->flags = htobe16(DNS_RECURSION_DESIRED);
    h->qdCount = htobe16(1);
    h->anCount = 0;
    h->nsCount = 0;
    h->arCount = 0;

    convert_hostname(reinterpret_cast<char*>(h + 1),name,nameLen);

    DNSQuestionEnd *qend = reinterpret_cast<DNSQuestionEnd*>(buffer + sizeof(*h) + nameLen + 2);
    qend->type = htobe16(TYPE_A);
    qend->cls = htobe16(CLASS_IN);

    // create socket
    auto sock = UdpSocket::create(netmng);
    sock->set_blocking(false);

    // send over socket
    sock->send_to(buffer, total, Endpoint(_nameserver, DNS_PORT));

    // wait for the response
    FileWaiter waiter;
    waiter.add(sock->fd(), File::INPUT);
    waiter.wait_for(timeout);

    // receive response
    ssize_t len = sock->recv(buffer, sizeof(buffer));
    if(len < static_cast<ssize_t>(sizeof(DNSHeader)))
        VTHROW(Errors::NOT_FOUND, "Received invalid DNS response");
    if(be16toh(h->id) != txid)
        VTHROW(Errors::NOT_FOUND, "Received DNS response with wrong transaction id");

    int questions = be16toh(h->qdCount);
    int answers = be16toh(h->anCount);

    // skip questions
    uint8_t *data = reinterpret_cast<uint8_t*>(h + 1);
    for(int i = 0; i < questions; ++i) {
        size_t len = question_length(data);
        data += len + sizeof(DNSQuestionEnd);
    }

    // parse answers
    for(int i = 0; i < answers; ++i) {
        DNSAnswer *ans = reinterpret_cast<DNSAnswer*>(data);
        if(be16toh(ans->type) == TYPE_A && be16toh(ans->length) == sizeof(IpAddr)) {
            uint8_t *bytes = data + sizeof(DNSAnswer);
            return IpAddr(bytes[0], bytes[1], bytes[2], bytes[3]);
        }
    }

    VTHROW(Errors::NOT_FOUND, "Unable to find IP address in DNS response");
}

} // namespace m3
