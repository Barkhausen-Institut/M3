/*
 * Copyright (C) 2023 Nils Asmussen, Barkhausen Institut
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

#include <base/Env.h>
#include <base/Init.h>
#include <base/TCU.h>
#include <base/TileDesc.h>
#include <base/arch/linux/Init.h>
#include <base/arch/linux/MMap.h>

#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>

namespace m3lx {

struct LinuxInit {
    LinuxInit();

    static int init_dev();
    static void init_env(int tcu_fd);

    int fd;
};

static INIT_PRIO_LXDEV LinuxInit lxdev;

int tcu_fd() {
    return lxdev.fd;
}

LinuxInit::LinuxInit() : fd(init_dev()) {
    mmap_tcu(fd, reinterpret_cast<void *>(m3::TCU::MMIO_ADDR), m3::TCU::MMIO_SIZE, MemType::TCU,
             m3::KIF::Perm::RW);
    init_env(fd);
#if defined(__hw__) || defined(__gem5__)
    mmap_tcu(fd, reinterpret_cast<void *>(m3::TCU::MMIO_EPS_ADDR), m3::TCU::endpoints_size(),
             MemType::TCUEps, m3::KIF::Perm::R);
#endif

    auto [rbuf_virt_addr, rbuf_size] = m3::TileDesc(m3::bootenv()->tile_desc).rbuf_std_space();
    mmap_tcu(fd, reinterpret_cast<void *>(rbuf_virt_addr), rbuf_size, MemType::StdRecvBuf,
             m3::KIF::Perm::R);
}

int LinuxInit::init_dev() {
    int fd = open("/dev/tcu", O_RDWR | O_SYNC);
    assert(fd != -1);
    return fd;
}

void LinuxInit::init_env(int tcu_fd) {
    mmap_tcu(tcu_fd, reinterpret_cast<void *>(m3::bootenv()), ENV_SIZE, MemType::Environment,
             m3::KIF::Perm::RW);
}

}
