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

#include "ops.h"

#include <base/TCU.h>

#include <m3/Exception.h>
#include <m3/stream/Standard.h>

#include <sstream>

#define DEBUG 0

using namespace m3;

Executor *Executor::create(const char *db) {
    return new LevelDBExecutor(db);
}

LevelDBExecutor::LevelDBExecutor(const char *db)
    : _t_insert(),
      _t_read(),
      _t_scan(),
      _t_update(),
      _n_insert(),
      _n_read(),
      _n_scan(),
      _n_update() {
    leveldb::Options options;
    options.create_if_missing = true;
    leveldb::Status status = leveldb::DB::Open(options, db, &_db);
    if(!status.ok()) {
        vthrow(Errors::INV_ARGS, "Unable to open/create DB '{}': {}"_cf, db,
               status.ToString().c_str());
    }
}

LevelDBExecutor::~LevelDBExecutor() {
    delete _db;
}

void LevelDBExecutor::reset_stats() {
    _n_insert = 0;
    _n_read = 0;
    _n_scan = 0;
    _n_update = 0;
    _t_insert = CycleDuration::from_raw(0);
    _t_read = CycleDuration::from_raw(0);
    _t_scan = CycleDuration::from_raw(0);
    _t_update = CycleDuration::from_raw(0);
}

void LevelDBExecutor::print_stats(size_t num_ops) {
    CycleDuration avg;
    println("    Key Value Database Timings for {} operations:"_cf, num_ops);

    avg = _n_insert > 0 ? _t_insert / _n_insert : CycleDuration::from_raw(0);
    println("        Insert: {},\t ops: {},\t avg_time: {}"_cf, _t_insert, _n_insert, avg);

    avg = _n_read > 0 ? _t_read / _n_read : CycleDuration::from_raw(0);
    println("        Read:   {},\t ops: {},\t avg_time: {}"_cf, _t_read, _n_read, avg);

    avg = _n_update > 0 ? _t_update / _n_update : CycleDuration::from_raw(0);
    println("        Update: {},\t ops: {},\t avg_time: {}"_cf, _t_update, _n_update, avg);

    avg = _n_scan > 0 ? _t_scan / _n_scan : CycleDuration::from_raw(0);
    println("        Scan:   {},\t ops: {},\t avg_time: {}"_cf, _t_scan, _n_scan, avg);
}

size_t LevelDBExecutor::execute(Package &pkg) {
#if DEBUG > 0
    print("Executing operation {} with table {}"_cf, (int)pkg.op, (int)pkg.table);
    print("  num_kvs={}, key={}"_cf, (int)pkg.num_kvs, pkg.key);
    println(", scan_length={}"_cf, pkg.scan_length);
#endif
#if DEBUG > 1
    for(auto &pair : pkg.kv_pairs)
        println("  key='field{}' val='{}'"_cf, pair.first.c_str(), pair.second.c_str());
#endif

    switch(pkg.op) {
        case ::Operation::INSERT: {
            auto start = CycleInstant::now();
            exec_insert(pkg);
            _t_insert += CycleInstant::now().duration_since(start);
            _n_insert++;
            return 4;
        }

        case ::Operation::UPDATE: {
            auto start = CycleInstant::now();
            exec_insert(pkg);
            _t_update += CycleInstant::now().duration_since(start);
            _n_update++;
            return 4;
        }

        case ::Operation::READ: {
            auto start = CycleInstant::now();
            auto vals = exec_read(pkg);
            size_t bytes = 0;
            for(auto &pair : vals) {
                bytes += pair.first.size() + pair.second.size();
#if DEBUG > 1
                println("  found '{}' -> '{}'"_cf, pair.first.c_str(), pair.second.c_str());
#endif
            }
            _t_read += CycleInstant::now().duration_since(start);
            _n_read++;
            return bytes;
        }

        case ::Operation::SCAN: {
            auto start = CycleInstant::now();
            auto vals = exec_scan(pkg);
            size_t bytes = 0;
            for(auto &pair : vals) {
                bytes += pair.first.size() + pair.second.size();
#if DEBUG > 1
                println("  found '{}'' -> '{}'"_cf, pair.first.c_str(), pair.second.c_str());
#endif
            }
            _t_scan += CycleInstant::now().duration_since(start);
            _n_scan++;
            return bytes;
        }

        case ::Operation::DELETE: eprintln("DELETE is not supported"_cf); return 4;
    }

    return 0;
}

static std::string pack_key(uint64_t key, const std::string &field, const char *prefix) {
    std::ostringstream key_field;
    key_field << key << "/" << prefix << field;
    return key_field.str();
}

static std::pair<uint64_t, std::string> unpack_key(const std::string &key_field) {
    size_t pos = 0;
    uint64_t key = static_cast<uint64_t>(std::stoll(key_field, &pos));
    std::string field = key_field.substr(pos + 1);
    return std::make_pair(key, field);
}

void LevelDBExecutor::exec_insert(Package &pkg) {
    leveldb::WriteOptions writeOptions;
    for(auto &pair : pkg.kv_pairs) {
        auto key = pack_key(pkg.key, pair.first, "field");
#if DEBUG > 1
        eprintln("Setting '{}' to '{}'"_cf, key.c_str(), pair.second.c_str());
#endif
        _db->Put(writeOptions, key, pair.second);
    }
}

std::vector<std::pair<std::string, std::string>> LevelDBExecutor::exec_read(Package &pkg) {
    std::vector<std::pair<std::string, std::string>> res;
    // If the k,v pairs are empty, this means "all fields" should be read
    if(pkg.kv_pairs.empty()) {
        leveldb::Iterator *it = _db->NewIterator(leveldb::ReadOptions());
        for(it->SeekToFirst(); it->Valid(); it->Next()) {
            std::istringstream is(it->key().ToString());
            uint64_t key;
            is >> key;
            if(key == pkg.key) {
                std::string field;
                is >> field;
                res.push_back(std::make_pair(field, it->value().ToString()));
            }
        }
    }
    else {
        for(auto &pair : pkg.kv_pairs) {
            auto key = pack_key(pkg.key, pair.first, "");
            std::string value;
            auto s = _db->Get(leveldb::ReadOptions(), key, &value);
            if(s.ok())
                res.push_back(std::make_pair(pair.first, value));
            else
                eprintln("Unable to find key '{}'"_cf, key.c_str());
        }
    }
    return res;
}

static bool take_field(Package &pkg, const std::string &field) {
    if(pkg.kv_pairs.empty())
        return true;
    for(auto &pair : pkg.kv_pairs) {
        if(pair.first == field)
            return true;
    }
    return false;
}

std::vector<std::pair<std::string, std::string>> LevelDBExecutor::exec_scan(Package &pkg) {
    std::vector<std::pair<std::string, std::string>> res;
    size_t rem = pkg.scan_length;
    uint64_t last_key = 0;
    leveldb::Iterator *it = _db->NewIterator(leveldb::ReadOptions());
    if(pkg.kv_pairs.size() == 1) {
        auto key = pack_key(pkg.key, pkg.kv_pairs.front().first, "");
        it->Seek(key);
    }
    else
        it->SeekToFirst();
    for(; rem > 0 && it->Valid(); it->Next()) {
        auto pair = unpack_key(it->key().ToString());
        if(pair.first >= pkg.key) {
            if(take_field(pkg, pair.second)) {
                res.push_back(std::make_pair(pair.second, it->value().ToString()));
                if(last_key && last_key != pair.first)
                    rem--;
            }
            last_key = pair.first;
        }
    }
    return res;
}
