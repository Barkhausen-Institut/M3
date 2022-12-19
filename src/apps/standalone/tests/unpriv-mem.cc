/*
 * Copyright (C) 2021-2022 Nils Asmussen, Barkhausen Institut
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

#include "../common.h"

using namespace m3;

static constexpr epid_t MEP = TCU::FIRST_USER_EP;
static constexpr epid_t MEP2 = TCU::FIRST_USER_EP + 1;
static constexpr epid_t SEP = TCU::FIRST_USER_EP + 2;
static constexpr epid_t REP = TCU::FIRST_USER_EP + 3;

static uint8_t src_buf[16384];
static uint8_t dst_buf[16384];
static uint8_t mem_buf[16384];

static void test_mem_short() {
    auto own_tile = TileId::from_raw(env()->tile_id);
    auto mem_tile = TILE_IDS[Tile::MEM];

    uint64_t data = 1234;

    ASSERT_EQ(kernel::TCU::unknown_cmd(), Errors::UNKNOWN_CMD);

    kernel::TCU::config_mem(MEP, mem_tile, 0x1000, sizeof(uint64_t), TCU::R | TCU::W);

    logln("WRITE with invalid arguments"_cf);
    {
        kernel::TCU::config_mem(MEP2, mem_tile, 0x1000, sizeof(uint64_t), TCU::R);
        kernel::TCU::config_send(SEP, 0x1234, own_tile, REP, 6 /* 64 */, 2);

        // not a memory EP
        ASSERT_EQ(kernel::TCU::write(SEP, &data, sizeof(data), 0), Errors::NO_MEP);
        // offset out of bounds
        ASSERT_EQ(kernel::TCU::write(MEP, &data, sizeof(data), 1), Errors::OUT_OF_BOUNDS);
        // size out of bounds
        ASSERT_EQ(kernel::TCU::write(MEP, &data, sizeof(data) + 1, 0), Errors::OUT_OF_BOUNDS);
        // no write permission
        ASSERT_EQ(kernel::TCU::write(MEP2, &data, sizeof(data), 0), Errors::NO_PERM);
    }

    logln("READ with invalid arguments"_cf);
    {
        kernel::TCU::config_mem(MEP2, mem_tile, 0x1000, sizeof(uint64_t), TCU::W);
        kernel::TCU::config_send(SEP, 0x1234, own_tile, REP, 6 /* 64 */, 2);

        // not a memory EP
        ASSERT_EQ(kernel::TCU::read(SEP, &data, sizeof(data), 0), Errors::NO_MEP);
        // offset out of bounds
        ASSERT_EQ(kernel::TCU::read(MEP, &data, sizeof(data), 1), Errors::OUT_OF_BOUNDS);
        // size out of bounds
        ASSERT_EQ(kernel::TCU::read(MEP, &data, sizeof(data) + 1, 0), Errors::OUT_OF_BOUNDS);
        // no read permission
        ASSERT_EQ(kernel::TCU::read(MEP2, &data, sizeof(data), 0), Errors::NO_PERM);
    }

    logln("READ+WRITE with offset = 0"_cf);
    {
        uint64_t data_ctrl = 0;
        ASSERT_EQ(kernel::TCU::write(MEP, &data, sizeof(data), 0), Errors::SUCCESS);
        ASSERT_EQ(kernel::TCU::read(MEP, &data_ctrl, sizeof(data), 0), Errors::SUCCESS);
        ASSERT_EQ(data, data_ctrl);
    }

    logln("READ+WRITE with offset != 0"_cf);
    {
        kernel::TCU::config_mem(MEP2, mem_tile, 0x2000, sizeof(uint64_t) * 2, TCU::R | TCU::W);

        uint64_t data_ctrl = 0;
        ASSERT_EQ(kernel::TCU::write(MEP2, &data, sizeof(data), 4), Errors::SUCCESS);
        ASSERT_EQ(kernel::TCU::read(MEP2, &data_ctrl, sizeof(data), 4), Errors::SUCCESS);
        ASSERT_EQ(data, data_ctrl);
    }

    logln("0-byte READ+WRITE transfers"_cf);
    {
        kernel::TCU::config_mem(MEP2, mem_tile, 0x2000, sizeof(uint64_t) * 2, TCU::R | TCU::W);

        ASSERT_EQ(kernel::TCU::write(MEP2, nullptr, 0, 0), Errors::SUCCESS);
        ASSERT_EQ(kernel::TCU::read(MEP2, nullptr, 0, 0), Errors::SUCCESS);
    }
}

static void test_mem_large(TileId mem_tile) {
    for(size_t i = 0; i < ARRAY_SIZE(src_buf); ++i)
        src_buf[i] = i;

    size_t addr = mem_tile.tile() == Tile::MEM ? 0x1000 : reinterpret_cast<size_t>(mem_buf);
    kernel::TCU::config_mem(MEP, mem_tile, addr, sizeof(src_buf), TCU::R | TCU::W);

    const size_t sizes[] = {64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384};
    for(auto size : sizes) {
        logln("READ+WRITE with {} bytes with {}"_cf, size, mem_tile);

        ASSERT_EQ(kernel::TCU::write(MEP, src_buf, size, 0), Errors::SUCCESS);
        ASSERT_EQ(kernel::TCU::read(MEP, dst_buf, size, 0), Errors::SUCCESS);
        for(size_t i = 0; i < size; ++i)
            ASSERT_EQ(src_buf[i], dst_buf[i]);
    }
}

static void test_mem_rdwr(TileId mem_tile) {
    for(size_t i = 0; i < ARRAY_SIZE(src_buf); ++i)
        src_buf[i] = i;

    size_t addr = mem_tile.tile() == Tile::MEM ? 0x1000 : reinterpret_cast<size_t>(mem_buf);
    kernel::TCU::config_mem(MEP, mem_tile, addr, sizeof(src_buf), TCU::R | TCU::W);

    const size_t sizes[] = {4096, 8192};
    for(auto size : sizes) {
        memset(dst_buf, 0, sizeof(dst_buf));

        logln("READ+WRITE+READ+WRITE with {} bytes with {}"_cf, size, mem_tile);

        // first write our data
        ASSERT_EQ(kernel::TCU::write(MEP, src_buf, size, 0), Errors::SUCCESS);
        // read it into a buffer for the next write
        ASSERT_EQ(kernel::TCU::read(MEP, dst_buf, size, 0), Errors::SUCCESS);
        // write the just read data
        ASSERT_EQ(kernel::TCU::write(MEP, dst_buf, size, 0), Errors::SUCCESS);
        // read it again for checking purposes
        ASSERT_EQ(kernel::TCU::read(MEP, dst_buf, size, 0), Errors::SUCCESS);
        for(size_t i = 0; i < size; ++i)
            ASSERT_EQ(src_buf[i], dst_buf[i]);
    }
}

template<typename DATA>
static void test_mem(size_t size_in) {
    auto mem_tile = TILE_IDS[Tile::MEM];

    logln("READ+WRITE with {} {}B words"_cf, size_in, sizeof(DATA));

    DATA buffer[size_in];

    // prepare test data
    DATA msg[size_in];
    for(size_t i = 0; i < size_in; ++i)
        msg[i] = i + 1;

    kernel::TCU::config_mem(MEP, mem_tile, 0x1000, size_in * sizeof(DATA), TCU::R | TCU::W);

    // test write + read
    ASSERT_EQ(kernel::TCU::write(MEP, msg, size_in * sizeof(DATA), 0), Errors::SUCCESS);
    ASSERT_EQ(kernel::TCU::read(MEP, buffer, size_in * sizeof(DATA), 0), Errors::SUCCESS);
    for(size_t i = 0; i < size_in; i++)
        ASSERT_EQ(buffer[i], msg[i]);
}

template<size_t PAD>
static void test_unaligned_rdwr(size_t nbytes, size_t loc_offset, size_t rem_offset) {
    auto mem_tile = TILE_IDS[Tile::MEM];

    // prepare test data
    UnalignedData<PAD> msg;
    msg.pre = 0xFF;
    msg.post = 0xFF;
    for(size_t i = 0; i < 16; ++i)
        msg.data[i] = i + 1;

    kernel::TCU::config_mem(MEP, mem_tile, 0x1000 + rem_offset, 0x1000, TCU::R | TCU::W);

    ASSERT_EQ(kernel::TCU::write(MEP, msg.data, nbytes, loc_offset), Errors::SUCCESS);
    ASSERT_EQ(kernel::TCU::read(MEP, msg.data, nbytes, loc_offset), Errors::SUCCESS);

    ASSERT_EQ(msg.pre, 0xFF);
    ASSERT_EQ(msg.post, 0xFF);
    for(size_t i = 0; i < nbytes; ++i)
        ASSERT_EQ(msg.data[i], i + 1);
}

void test_mem() {
    test_mem_short();
    test_mem_large(TILE_IDS[Tile::MEM]);
    test_mem_large(TILE_IDS[Tile::T0]);
    test_mem_rdwr(TILE_IDS[Tile::MEM]);

    // test different lengths
    for(size_t i = 1; i <= 80; i++) {
        test_mem<uint8_t>(i);
        test_mem<uint16_t>(i);
        test_mem<uint32_t>(i);
        test_mem<uint64_t>(i);
    }

    // test different alignments
    logln("Test READ+WRITE with different alignments"_cf);
    for(size_t nbytes = 1; nbytes < 16; ++nbytes) {
        for(size_t loc_off = 0; loc_off < 16; ++loc_off) {
            for(size_t rem_off = 0; rem_off < 16; ++rem_off) {
                test_unaligned_rdwr<1>(nbytes, loc_off, rem_off);
                test_unaligned_rdwr<2>(nbytes, loc_off, rem_off);
                test_unaligned_rdwr<3>(nbytes, loc_off, rem_off);
                test_unaligned_rdwr<4>(nbytes, loc_off, rem_off);
                test_unaligned_rdwr<5>(nbytes, loc_off, rem_off);
                test_unaligned_rdwr<6>(nbytes, loc_off, rem_off);
                test_unaligned_rdwr<7>(nbytes, loc_off, rem_off);
                test_unaligned_rdwr<8>(nbytes, loc_off, rem_off);
                test_unaligned_rdwr<9>(nbytes, loc_off, rem_off);
                test_unaligned_rdwr<10>(nbytes, loc_off, rem_off);
                test_unaligned_rdwr<11>(nbytes, loc_off, rem_off);
                test_unaligned_rdwr<12>(nbytes, loc_off, rem_off);
                test_unaligned_rdwr<13>(nbytes, loc_off, rem_off);
                test_unaligned_rdwr<14>(nbytes, loc_off, rem_off);
                test_unaligned_rdwr<15>(nbytes, loc_off, rem_off);
                test_unaligned_rdwr<16>(nbytes, loc_off, rem_off);
            }
        }
    }
}
