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

#pragma once

#include <m3/net/Net.h>
#include <m3/net/TcpSocket.h>
#include <m3/net/UdpSocket.h>
#include <m3/session/NetworkManager.h>

#include "ops.h"

#define SYSC_RECEIVE 0xFFFF
#define SYSC_SEND    0xFFFE

extern "C" void __m3_sysc_trace(bool enable, size_t max);
extern "C" void __m3_sysc_trace_start(long n);
extern "C" void __m3_sysc_trace_stop();
extern "C" uint64_t __m3_sysc_systime();

class OpHandler {
public:
    enum Result {
        READY,
        INCOMPLETE,
        STOP,
    };

    virtual ~OpHandler() {
    }

    virtual Result receive(Package &pkg, m3::CycleInstant &start) = 0;
    virtual bool respond(m3::CycleDuration total, m3::CycleDuration xfer, size_t bytes);
    virtual void reset() {
    }

    virtual m3::Option<size_t> send(const void *data, size_t len) = 0;

    static uint64_t read_u64(const uint8_t *bytes);
    static size_t from_bytes(const uint8_t *package_buffer, size_t package_size, Package &pkg);
};

class TCPOpHandler : public OpHandler {
public:
    explicit TCPOpHandler(m3::NetworkManager &nm, m3::port_t port);

    virtual Result receive(Package &pkg, m3::CycleInstant &start) override;

private:
    m3::Option<size_t> send(const void *data, size_t len) override;
    m3::Option<size_t> receive(void *data, size_t max);

    m3::FileRef<m3::TcpSocket> _socket;
};

class UDPOpHandler : public OpHandler {
public:
    explicit UDPOpHandler(m3::NetworkManager &nm, const char *workload, m3::IpAddr ip,
                          m3::port_t port);

    virtual Result receive(Package &pkg, m3::CycleInstant &start) override;
    virtual void reset() override;

private:
    m3::Option<size_t> send(const void *data, size_t len) override;

    uint64_t _ops;
    uint64_t _total_ops;
    m3::Endpoint _ep;
    m3::FileRef<m3::UdpSocket> _socket;
};

class TCUOpHandler : public OpHandler {
    const size_t MAX_RESULT_SIZE = 1024 * 1024;

public:
    explicit TCUOpHandler();

    virtual Result receive(Package &pkg, m3::CycleInstant &start) override;
    virtual bool respond(m3::CycleDuration total, m3::CycleDuration xfer, size_t bytes) override;

private:
    m3::Option<size_t> send(const void *data, size_t len) override;
    m3::Option<size_t> receive(void *data, size_t max);

    m3::RecvGate _rgate;
    m3::MemGate _result;
    m3::GateIStream *_last_req;
};
