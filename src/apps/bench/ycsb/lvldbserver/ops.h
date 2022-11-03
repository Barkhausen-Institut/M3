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

#include <base/time/Duration.h>

#include <stdint.h>
#include <string>
#include <vector>

#include "leveldb/db.h"

enum Operation {
    INSERT = 1,
    DELETE = 2,
    READ = 3,
    SCAN = 4,
    UPDATE = 5,
};

struct Package {
    uint8_t op;
    uint8_t table;
    uint8_t num_kvs;
    uint64_t key;
    uint64_t scan_length;
    std::vector<std::pair<std::string, std::string>> kv_pairs;
};

class Executor {
public:
    static Executor *create(const char *db);

    virtual ~Executor() {
    }
    virtual size_t execute(Package &pkg) = 0;
    virtual void reset_stats() = 0;
    virtual void print_stats(size_t num_ops) = 0;
};

class LevelDBExecutor : public Executor {
public:
    explicit LevelDBExecutor(const char *db);
    ~LevelDBExecutor();

    virtual size_t execute(Package &pkg) override;
    virtual void reset_stats() override;
    virtual void print_stats(size_t num_ops) override;

private:
    void exec_insert(Package &pkg);
    std::vector<std::pair<std::string, std::string>> exec_read(Package &pkg);
    std::vector<std::pair<std::string, std::string>> exec_scan(Package &pkg);
    void exec_update(Package &pkg);

    m3::CycleDuration _t_insert;
    m3::CycleDuration _t_read;
    m3::CycleDuration _t_scan;
    m3::CycleDuration _t_update;
    uint64_t _n_insert;
    uint64_t _n_read;
    uint64_t _n_scan;
    uint64_t _n_update;

    leveldb::DB *_db;
};
