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

#pragma once

#include <base/time/Duration.h>
#include <base/util/Random.h>

#include <m3/net/Net.h>

namespace m3 {

class NetworkManager;

/**
 * Implements the DNS protocol to resolve host names to IP addresses.
 */
class DNS {
    friend class NetworkManager;

public:
    /**
     * Creates a new DNS resolver
     */
    explicit DNS()
        : _rng(),
          _nameserver() {
    }

    /**
     * Checks whether the given hostname is an IP address.
     *
     * @param name the hostname
     * @return true if so
     */
    static bool is_ip_addr(const char *name);

    /**
     * Translates the given name into an IP address. If the name is already an IP address, it will
     * simply be converted into an [`IpAddr`] object. Otherwise, the name will be solved via DNS.
     *
     * @param netmng the network manager
     * @param name the hostname
     * @param timeout specifies the maximum time we wait for the DNS response
     * @return the IP address
     * @throws if the operation failed
     */
    IpAddr get_addr(NetworkManager &netmng, const char *name, TimeDuration timeout = TimeDuration::from_secs(3));

    /**
     * Resolves the given hostname to an IP address. Note that this method assumes that the name is
     * not an IP address, but an actual hostname and will therefore always use DNS to resolve the
     * name. Use get_addr() if you don't know whether it's a hostname or an IP address.
     *
     * @param netmng the network manager
     * @param name the domain name
     * @param timeout specifies the maximum time we wait for the DNS response
     * @return the ip address
     * @throws if the operation failed
     */
    IpAddr resolve(NetworkManager &netmng, const char *name, TimeDuration timeout = TimeDuration::from_secs(3));

private:
    Random _rng;
    IpAddr _nameserver;
};

}
