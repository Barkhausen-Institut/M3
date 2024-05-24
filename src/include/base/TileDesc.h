/*
 * Copyright (C) 2016-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019-2022 Nils Asmussen, Barkhausen Institut
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

#include <base/Common.h>
#include <base/Config.h>

#include <utility>

namespace m3 {

/**
 * The different types of tiles
 */
enum class TileType {
    // Compute tile
    COMP = 0,
    // memory tile
    MEM = 1,
};

/**
 * The different ISAs
 */
enum class TileISA {
    NONE = 0,
    RISCV64 = 1,
    RISCV32 = 2,
    X86 = 3,
    ACCEL_INDIR = 4,
    ACCEL_COPY = 5,
    ACCEL_ROT13 = 6,
    IDE_DEV = 7,
    NIC_DEV = 8,
    SERIAL_DEV = 9,
};

enum TileAttr {
    PERF = 1 << 0,
    EFFI = 1 << 1,
    NIC = 1 << 2,
    SERIAL = 1 << 3,
    IMEM = 1 << 4,
    IEPS = 1 << 5,
    KECACC = 1 << 6,
};

/**
 * Describes a tile
 */
struct TileDesc {
    typedef uint64_t value_t;

    /**
     * Default constructor
     */
    explicit TileDesc() : _value() {
    }
    /**
     * Creates a tile description from the given descriptor word
     */
    explicit TileDesc(value_t value) : _value(value) {
    }
    /**
     * Creates a tile description of given type, ISA and memory size
     */
    explicit TileDesc(TileType type, TileISA isa, size_t memsize = 0, uint attr = 0)
        : _value(static_cast<value_t>(type) | (static_cast<value_t>(isa) << 6) |
                 (static_cast<value_t>(attr) << 11) | ((memsize >> 12) << 28)) {
    }

    /**
     * @return the raw descriptor word
     */
    value_t value() const {
        return _value;
    }

    /**
     * @return the type of tile
     */
    TileType type() const {
        return static_cast<TileType>(_value & 0x3F);
    }
    /**
     * @return the isa of the tile
     */
    TileISA isa() const {
        return static_cast<TileISA>((_value >> 6) & 0x1F);
    }
    /**
     * @return the attributes of the tile
     */
    uint attr() const {
        return (_value >> 11) & 0x1FFFF;
    }
    /**
     * @return if the tile has a core that is programmable
     */
    bool is_programmable() const {
        return isa() != TileISA::NONE && isa() < TileISA::ACCEL_INDIR;
    }
    /**
     * @return if the tile supports multiple contexts
     */
    bool is_device() const {
        return isa() == TileISA::NIC_DEV || isa() == TileISA::IDE_DEV ||
               isa() == TileISA::SERIAL_DEV;
    }

    /**
     * @return if the tile supports activities
     */
    bool supports_activities() const {
        return type() != TileType::MEM;
    }
    /**
     * @return if the tile supports the context switching protocol
     */
    bool supports_tilemux() const {
        return supports_activities() && !is_device();
    }

    /**
     * @return the memory offset within the physical address space of the tile
     */
    size_t mem_offset() const {
        return isa() == TileISA::RISCV64 ? 0x1000'0000 : 0;
    }

    /**
     * @return the memory size (if has_memory() == true)
     */
    size_t mem_size() const {
        return (_value >> 28) << 12;
    }
    /**
     * @return true if the tile has internal memory
     */
    bool has_memory() const {
        return type() == TileType::MEM || (attr() & IMEM) != 0;
    }
    /**
     * @return true if the tile has virtual memory support of some form
     */
    bool has_virtmem() const {
        return !has_memory() && !is_device();
    }

    /**
     * @return true if the tile has internal endpoints
     */
    bool has_internal_eps() const {
        return (attr() & TileAttr::IEPS) != 0;
    }

    /**
     * @return the starting address and size of the environment
     */
    std::pair<uintptr_t, size_t> env_space() const {
        auto offset = isa() == TileISA::RISCV64 ? PAGE_SIZE : 0x1F'E000;
        auto start = isa() == TileISA::RISCV32 ? 0x1'0000 : mem_offset() + offset;
        return std::make_pair(start, PAGE_SIZE);
    }

    /**
     * @return the starting address and size of the standard receive buffer space
     */
    std::pair<uintptr_t, size_t> rbuf_std_space() const {
        return std::make_pair(rbuf_base(), RBUF_STD_SIZE);
    }

    /**
     * @return the starting address and size of the receive buffer space
     */
    std::pair<uintptr_t, size_t> rbuf_space() const {
        size_t size = has_virtmem() ? RBUF_SIZE : RBUF_SIZE_SPM;
        return std::make_pair(rbuf_base() + RBUF_STD_SIZE, size);
    }

    /**
     * @return the highest address of the stack
     */
    uintptr_t stack_top() const {
        auto space = stack_space();
        return space.first + space.second;
    }

    /**
     * @return the starting address and size of the stack
     */
    std::pair<uintptr_t, size_t> stack_space() const {
        return std::make_pair(rbuf_base() - STACK_SIZE, STACK_SIZE);
    }

private:
    uintptr_t rbuf_base() const {
        if(has_virtmem())
            return RBUF_STD_ADDR;
        size_t rbufs = RBUF_SIZE_SPM + RBUF_STD_SIZE;
        return mem_offset() + mem_size() - rbufs;
    }

    value_t _value;
} PACKED;

}
