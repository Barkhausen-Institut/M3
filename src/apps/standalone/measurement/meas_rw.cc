/*
 * Copyright (C) 2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
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
#include <base/stream/Serial.h>
#include <base/time/Instant.h>
#include <base/TCU.h>

#include "../assert.h"
#include "../tcuif.h"

#include "../tiles.h"
//#include "../tiles_bic1.h"

using namespace m3;

#define CLKFREQ_MHZ 100

#define MEAS_DATA_SIZE 64    //32 or 64

#define DO_WRITE
#define DO_READ

static constexpr epid_t MEP = TCU::FIRST_USER_EP;

static constexpr size_t TESTDATA_START = 1024;
static constexpr size_t TESTDATA_INCR  = 1024;
static constexpr size_t TESTDATA_SIZE  = 1024;

static constexpr size_t ITER_MAX  = 500000;

static constexpr goff_t DRAM_OFF = 0x10000000;

TileId local_tile;
TileId remote_tile;
goff_t remote_addr;

#if (MEAS_DATA_SIZE == 32)
static uint32_t src_buf[TESTDATA_SIZE];
static uint32_t dst_buf[TESTDATA_SIZE];
#else
static uint64_t src_buf[TESTDATA_SIZE];
static uint64_t dst_buf[TESTDATA_SIZE];
#endif

static cycles_t results_write[TESTDATA_SIZE/TESTDATA_INCR];
static cycles_t results_read[TESTDATA_SIZE/TESTDATA_INCR];

size_t time_idx_write = 0;
size_t time_idx_read = 0;



cycles_t nanos_diff_to_cycles(uint64_t start_nanos, uint64_t end_nanos) {
    return (end_nanos-start_nanos)*CLKFREQ_MHZ/1000;
}


template<typename DATA>
void test_mem_write(size_t size_in) {
    uint64_t start_nanos, end_nanos;

    // prepare test data
    DATA *testdata = (DATA*)src_buf;
    for(size_t i = 0; i < size_in; ++i)
        testdata[i] = i + 1;

    kernel::TCU::config_mem(MEP, remote_tile, remote_addr, size_in * sizeof(DATA), TCU::W);

    logln("test_mem_write with {} iterations"_cf, ITER_MAX);
    start_nanos = kernel::TCU::nanotime();
    for (size_t iter=0; iter<ITER_MAX; iter++) {
        ASSERT_EQ(kernel::TCU::write(MEP, testdata, size_in * sizeof(DATA), 0), Errors::SUCCESS);
    }
    end_nanos = kernel::TCU::nanotime();

    results_write[time_idx_write++] = nanos_diff_to_cycles(start_nanos, end_nanos)/ITER_MAX;
}

template<typename DATA>
void test_mem_read(size_t size_in) {
    DATA *buffer = (DATA*)dst_buf;
    uint64_t start_nanos, end_nanos;

    kernel::TCU::config_mem(MEP, remote_tile, remote_addr, size_in * sizeof(DATA), TCU::R);

    logln("test_mem_read with {} iterations"_cf, ITER_MAX);
    start_nanos = kernel::TCU::nanotime();
    for (size_t iter=0; iter<ITER_MAX; iter++) {
        ASSERT_EQ(kernel::TCU::read(MEP, buffer, size_in * sizeof(DATA), 0), Errors::SUCCESS);
    }
    end_nanos = kernel::TCU::nanotime();

    results_read[time_idx_read++] = nanos_diff_to_cycles(start_nanos, end_nanos)/ITER_MAX;

    //check data from test_mem_write
#ifdef DO_WRITE
    for (size_t i=0; i<size_in; i++) {
        ASSERT_EQ(buffer[i], i+1);
    }
#endif
}

int main() {
    //check on which tile this code runs
    //this code should not run on T0 because this is used to write to
    local_tile = TileId::from_raw(env()->tile_id);
    if (local_tile.raw() == TILE_IDS[Tile::T0].raw()) {
        logln("This is {}. Do not run this code on T0!\n"_cf, local_tile);
        logln("Shutting down"_cf);
        return 0;
    }

    //take T0 as remote
    size_t local_idx = tile_idx(local_tile).unwrap();
    remote_tile = TILE_IDS[Tile::T0];
    //remote_addr = local_idx*DRAM_OFF;
    remote_addr = DRAM_OFF + local_idx*0x00100000;

    logln("This is {}. Run measurement with {}, addr {:#x}.\n"_cf, local_tile, remote_tile, remote_addr);


    //init buf to store measurement times
    for (size_t i=0; i<TESTDATA_SIZE/TESTDATA_INCR; i++) {
        results_write[i] = 0;
        results_read[i] = 0;
    }

    logln("Starting measurement"_cf);
    for (size_t mem_size=TESTDATA_START; mem_size<=TESTDATA_SIZE; mem_size+=TESTDATA_INCR) {
        logln("num. of elements: {}"_cf, mem_size);

#ifdef DO_WRITE
#if (MEAS_DATA_SIZE == 32)
        test_mem_write<uint32_t>(mem_size);
#else
        test_mem_write<uint64_t>(mem_size);
#endif
#endif

#ifdef DO_READ
#if (MEAS_DATA_SIZE == 32)
        test_mem_read<uint32_t>(mem_size);
#else        
        test_mem_read<uint64_t>(mem_size);
#endif
#endif
    }

#ifdef DO_WRITE
    logln("\nResults WRITE (cycles):"_cf);
    for (size_t i=0; i<time_idx_write; i++) {
        logln("{}"_cf, results_write[i]);
    }
#endif

#ifdef DO_READ
    logln("\nResults READ (cycles):"_cf);
    for (size_t i=0; i<time_idx_read; i++) {
        logln("{}"_cf, results_read[i]);
    }
#endif


    //give the other tiles some time to finish
    auto end = TimeInstant::now() + TimeDuration::from_millis(50);
    while(TimeInstant::now() < end);

    logln(""_cf);
    logln("Shutting down"_cf);
    return 0;
}
