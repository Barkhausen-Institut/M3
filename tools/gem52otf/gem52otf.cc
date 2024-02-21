/*
 * Copyright (C) 2015, Matthias Lieber <matthias.lieber@tu-dresden.de>
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

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <iomanip>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRACE_FUNCS_TO_STRING

#include <algorithm>
#include <array>
#include <iostream>
#include <map>
#include <otf.h>
#include <queue>
#include <regex>
#include <set>
#include <unordered_map>
#include <vector>

#include "Symbols.h"

static bool verbose = 1;
static const uint64_t GEM5_TICKS_PER_SEC = 1000000000;
static const int GEM5_MAX_ACTS = 1024 + 1;
static const unsigned PRIV_ACTID = 0xFFFF;
static const unsigned IDLE_ACTID = 0xFFFE;

enum event_type {
    EVENT_FUNC_ENTER = 1,
    EVENT_FUNC_EXIT,
    EVENT_UFUNC_ENTER,
    EVENT_UFUNC_EXIT,
    EVENT_MSG_SEND_START,
    EVENT_MSG_SEND_DONE,
    EVENT_MSG_RECV,
    EVENT_MEM_READ_START,
    EVENT_MEM_READ_DONE,
    EVENT_MEM_WRITE_START,
    EVENT_MEM_WRITE_DONE,
    EVENT_SUSPEND,
    EVENT_WAKEUP,
    EVENT_SET_ACTID,
};

static const char *event_names[] = {
    "",
    "EVENT_FUNC_ENTER",
    "EVENT_FUNC_EXIT",
    "EVENT_UFUNC_ENTER",
    "EVENT_UFUNC_EXIT",
    "EVENT_MSG_SEND_START",
    "EVENT_MSG_SEND_DONE",
    "EVENT_MSG_RECV",
    "EVENT_MEM_READ_START",
    "EVENT_MEM_READ_DONE",
    "EVENT_MEM_WRITE_START",
    "EVENT_MEM_WRITE_DONE",
    "EVENT_SUSPEND",
    "EVENT_WAKEUP",
    "EVENT_SET_ACTID",
};

struct TileId {
    uint16_t chip;
    uint16_t tile;

    explicit TileId() : chip(), tile() {
    }
    explicit TileId(uint16_t chip, uint16_t tile) : chip(chip), tile(tile) {
    }

    uint32_t raw() const {
        return static_cast<uint32_t>(chip) << 16 | tile;
    }

    bool operator==(const TileId &other) const {
        return chip == other.chip && tile == other.tile;
    }

    friend std::istream &operator>>(std::istream &is, TileId &t) {
        uint16_t chip, tile;
        is.get(); // C
        is >> chip;
        is.get(); // T
        is >> tile;
        t = TileId(chip, tile);
        return is;
    }

    friend std::ostream &operator<<(std::ostream &os, const TileId &t) {
        if(t.chip == 0xFFFF)
            os << t.tile;
        else
            os << "C" << t.chip << "T" << std::setw(2) << std::setfill('0') << t.tile;
        return os;
    }
};

template<>
struct std::hash<TileId> {
    size_t operator()(const TileId &t) const {
        size_t res = 17;
        res = res * 31 + std::hash<uint16_t>()(t.chip);
        res = res * 31 + std::hash<uint16_t>()(t.tile);
        return res;
    }
};

struct Event {
    explicit Event()
        : tile(),
          timestamp(),
          type(),
          size(),
          remote(),
          tag(),
          bin(static_cast<uint32_t>(-1)),
          name() {
    }
    explicit Event(TileId tile, uint64_t ts, int type, size_t size, TileId remote, uint64_t tag)
        : tile(tile),
          timestamp(ts / 1000),
          type(type),
          size(size),
          remote(remote),
          tag(tag),
          bin(static_cast<uint32_t>(-1)),
          name() {
    }
    explicit Event(TileId tile, uint64_t ts, int type, uint32_t bin, const char *name)
        : tile(tile),
          timestamp(ts / 1000),
          type(type),
          size(),
          remote(),
          tag(),
          bin(bin),
          name(name) {
    }

    const char *tag_to_string() const {
        static char buf[5];
        buf[0] = static_cast<char>((tag >> 24) & 0xFF);
        buf[1] = static_cast<char>((tag >> 16) & 0xFF);
        buf[2] = static_cast<char>((tag >> 8) & 0xFF);
        buf[3] = static_cast<char>((tag >> 0) & 0xFF);
        buf[4] = '\0';
        return buf;
    }

    friend std::ostream &operator<<(std::ostream &os, const Event &ev) {
        os << ev.tile << " " << event_names[ev.type] << ": " << ev.timestamp;
        switch(ev.type) {
            case EVENT_FUNC_ENTER:
            case EVENT_FUNC_EXIT: os << " function: unknown (" << ev.tag << ")"; break;

            case EVENT_UFUNC_ENTER:
            case EVENT_UFUNC_EXIT: os << " function: " << ev.name; break;

            default:
                os << "  receiver: " << ev.remote << "  size: " << ev.size << "  tag: " << ev.tag;
                break;
        }
        return os;
    }

    TileId tile;
    uint64_t timestamp;

    int type;

    size_t size;
    TileId remote;
    uint64_t tag;

    uint32_t bin;
    const char *name;
};

struct State {
    static const size_t INVALID_IDX = static_cast<size_t>(-1);

    explicit State() : tag(), addr(), sym(), in_cmd(), have_start(), start_idx(INVALID_IDX) {
    }

    uint64_t tag;
    unsigned long addr;
    Symbols::symbol_t sym;
    bool in_cmd;
    bool have_start;
    size_t start_idx;
};

struct Stats {
    unsigned total = 0;
    unsigned send = 0;
    unsigned recv = 0;
    unsigned read = 0;
    unsigned write = 0;
    unsigned finish = 0;
    unsigned ufunc_enter = 0;
    unsigned ufunc_exit = 0;
    unsigned func_enter = 0;
    unsigned func_exit = 0;
    unsigned warnings = 0;
};

enum Mode {
    MODE_TILES,
    MODE_ACTS,
};

static Symbols syms;

static Event build_event(event_type type, uint64_t timestamp, TileId tile,
                         const std::string &remote, const std::string &size, uint64_t tag) {
    TileId remoteTile;
    if(!remote.empty()) {
        std::istringstream is(remote);
        is >> remoteTile;
    }

    Event ev(tile, timestamp, type, strtoull(size.c_str(), nullptr, 10), remoteTile, tag);
    return ev;
}

std::unordered_map<TileId, State> read_trace_file(const char *path, Mode mode,
                                                  std::vector<Event> &buf) {
    std::unordered_map<TileId, State> states;

    char filename[256];
    char readbuf[256];
    if(path) {
        strncpy(filename, path, sizeof(filename));
        filename[sizeof(filename) - 1] = '\0';
    }

    printf("reading trace file: %s\n", filename);

    FILE *fd = fopen(filename, "r");
    if(!fd) {
        perror("cannot open trace file");
        return states;
    }

    std::regex msg_snd_regex(
        "^: \e\\[1m\\[(?:sd|rp) -> (C\\d+T\\d+)\\]\e\\[0m with EP\\d+ of (?:0x)?[0-9a-f]+:(\\d+)");
    std::regex msg_rcv_regex("^: \e\\[1m\\[rv <- (C\\d+T\\d+)\\]\e\\[0m (\\d+) bytes on EP\\d+");
    std::regex msg_rw_regex(
        "^: \e\\[1m\\[(rd|wr) -> (C\\d+T\\d+)\\]\e\\[0m at (?:0x)?[0-9a-f]+\\+(?:0x)?[0-9a-f]+"
        " with EP\\d+ (?:from|into) (?:0x)?[0-9a-f]+:(\\d+)");
    std::regex suswake_regex("(Suspending|Waking up) core");
    std::regex setact_regex("^\\.regFile: TCU-> PRI\\[CUR_ACT     \\]: 0x([0-9a-f]+)");
    std::regex debug_regex("^: DEBUG (?:0x)([0-9a-f]+)");
    std::regex exec_regex("^(?:0x)([0-9a-f]+) @ .*  :");
    std::regex call_regex("^(?:0x)([0-9a-f]+) @ .*  :   CALL_NEAR");
    std::regex ret_regex("^(?:0x)([0-9a-f]+) @ .*\\.0  :   RET_NEAR");

    uint64_t tag = 1;

    std::smatch match;

    unsigned long long timestamp;
    while(fgets(readbuf, sizeof(readbuf), fd)) {
        unsigned long addr;
        TileId tile;
        unsigned _chip, _tile;
        int numchars;
        int tid;

        if(mode == MODE_ACTS && sscanf(readbuf, "%Lu: C%uT%u.cpu T%d : %lx @", &timestamp, &_chip,
                                       &_tile, &tid, &addr) == 5) {
            tile.tile = _tile;
            tile.chip = _chip;
            if(states[tile].addr == addr)
                continue;

            unsigned long oldaddr = states[tile].addr;
            states[tile].addr = addr;

            Symbols::symbol_t sym = syms.resolve(addr);
            if(states[tile].sym == sym)
                continue;

            if(oldaddr)
                buf.push_back(Event(tile, timestamp, EVENT_UFUNC_EXIT, 0, ""));

            uint32_t bin;
            char *namebuf = (char *)malloc(Symbols::MAX_FUNC_LEN + 1);
            if(!syms.valid(sym)) {
                bin = static_cast<uint32_t>(-1);
                snprintf(namebuf, Symbols::MAX_FUNC_LEN, "%#lx", addr);
            }
            else {
                bin = sym->bin;
                syms.demangle(namebuf, Symbols::MAX_FUNC_LEN, sym->name.c_str());
            }

            buf.push_back(Event(tile, timestamp, EVENT_UFUNC_ENTER, bin, namebuf));

            states[tile].sym = sym;
            continue;
        }

        // read only up to the end of the tile id to ensure that it matches until the end if scanf
        // reports that 2 conversions were done.
        if(sscanf(readbuf, "%Lu: C%uT%u%n", &timestamp, &_chip, &_tile, &numchars) != 3)
            continue;
        tile = TileId(_chip, _tile);

        // now that we know that, check if the following is indeed ".tcu" and only then continue
        if(strncmp(readbuf + numchars, ".tcu", 4) != 0)
            continue;

        numchars += 4;
        std::string line(readbuf + numchars);

        if(strstr(line.c_str(), "rv") && std::regex_search(line, match, msg_rcv_regex)) {
            TileId sender;
            std::istringstream is(match[1]);
            is >> sender;

            Event ev = build_event(EVENT_MSG_RECV, timestamp, tile, match[1].str(), match[2].str(),
                                   states[sender].tag);
            buf.push_back(ev);
        }
        else if(strstr(line.c_str(), "ing") && std::regex_search(line, match, suswake_regex)) {
            event_type type = match[1].str() == "Waking up" ? EVENT_WAKEUP : EVENT_SUSPEND;
            buf.push_back(build_event(type, timestamp, tile, "", "", tag));

            states[tile].tag = tag++;
        }
        else if(strstr(line.c_str(), "CUR_ACT") && std::regex_search(line, match, setact_regex)) {
            uint32_t acttag = strtoul(match[1].str().c_str(), NULL, 16) & 0xFFFF;
            buf.push_back(build_event(EVENT_SET_ACTID, timestamp, tile, "", "", acttag));
        }
        else if(mode == MODE_ACTS && std::regex_search(line, match, debug_regex)) {
            uint64_t value = strtoul(match[1].str().c_str(), NULL, 16);
            if(value >> 48 != 0) {
                event_type type = static_cast<event_type>(value >> 48);
                uint64_t acttag = value & 0xFFFFFFFFFFFF;
                buf.push_back(build_event(type, timestamp, tile, "", "", acttag));
            }
        }
        else if(!states[tile].in_cmd) {
            if(strncmp(line.c_str(), ": Starting command ", 19) == 0) {
                states[tile].in_cmd = true;
                states[tile].have_start = false;
            }
        }
        else {
            if(strncmp(line.c_str(), ": Finished command ", 19) == 0) {
                if(states[tile].have_start) {
                    int type;
                    assert(states[tile].start_idx != State::INVALID_IDX);
                    const Event &start_ev = buf[states[tile].start_idx];
                    if(start_ev.type == EVENT_MSG_SEND_START)
                        type = EVENT_MSG_SEND_DONE;
                    else if(start_ev.type == EVENT_MEM_READ_START)
                        type = EVENT_MEM_READ_DONE;
                    else
                        type = EVENT_MEM_WRITE_DONE;
                    TileId remote = start_ev.remote;
                    Event ev(tile, timestamp, type, start_ev.size, remote, states[tile].tag);
                    buf.push_back(ev);

                    states[tile].start_idx = State::INVALID_IDX;
                }

                states[tile].in_cmd = false;
            }
            else {
                if((strstr(line.c_str(), "sd") || strstr(line.c_str(), "rp")) &&
                   std::regex_search(line, match, msg_snd_regex)) {
                    Event ev = build_event(EVENT_MSG_SEND_START, timestamp, tile, match[1].str(),
                                           match[2].str(), tag);
                    states[tile].have_start = true;
                    buf.push_back(ev);
                    states[tile].start_idx = buf.size() - 1;
                    states[tile].tag = tag++;
                }
                else if((strstr(line.c_str(), "rd") || strstr(line.c_str(), "wr")) &&
                        std::regex_search(line, match, msg_rw_regex)) {
                    event_type type = match[1].str() == "rd" ? EVENT_MEM_READ_START
                                                             : EVENT_MEM_WRITE_START;
                    if(states[tile].start_idx != State::INVALID_IDX)
                        buf[states[tile].start_idx].size +=
                            strtoull(match[3].str().c_str(), nullptr, 10);
                    else {
                        Event ev =
                            build_event(type, timestamp, tile, match[2].str(), match[3].str(), tag);
                        states[tile].have_start = true;
                        buf.push_back(ev);
                        states[tile].start_idx = buf.size() - 1;
                        states[tile].tag = tag++;
                    }
                }
            }
        }
    }

    for(const std::pair<TileId, State> s : states) {
        if(s.second.addr)
            buf.push_back(Event(s.first, ++timestamp, EVENT_UFUNC_EXIT, 0, ""));
    }

    fclose(fd);
    return states;
}

static void gen_pe_events(OTF_Writer *writer, Stats &stats, std::vector<Event> &trace_buf,
                          std::unordered_map<TileId, State> &states) {
    // Processes.
    uint32_t stream = 1;
    for(const std::pair<TileId, State> s : states) {
        char peName[8];
        snprintf(peName, sizeof(peName), "C%huT%02hu", s.first.chip, s.first.tile);
        OTF_Writer_writeDefProcess(writer, 0, s.first.raw(), peName, 0);
        OTF_Writer_assignProcess(writer, s.first.raw(), stream);
    }

    // Process groups
    size_t i = 0;
    uint32_t allPEs[states.size()];
    for(const std::pair<TileId, State> s : states) {
        allPEs[i] = s.first.raw();
        i++;
    }

    unsigned grp_mem = (1 << 20) + 1;
    OTF_Writer_writeDefProcessGroup(writer, 0, grp_mem, "Memory Read/Write", states.size(), allPEs);
    unsigned grp_msg = (1 << 20) + 2;
    OTF_Writer_writeDefProcessGroup(writer, 0, grp_msg, "Message Send/Receive", states.size(),
                                    allPEs);

    // Function groups
    unsigned grp_func_count = 0;
    unsigned grp_func_exec = grp_func_count++;
    OTF_Writer_writeDefFunctionGroup(writer, 0, grp_func_exec, "Execution");

    // Execution functions
    unsigned fn_exec_last = (2 << 20) + 0;
    std::map<unsigned, unsigned> actfuncs;

    unsigned fn_exec_sleep = ++fn_exec_last;
    OTF_Writer_writeDefFunction(writer, 0, fn_exec_sleep, "Sleeping", grp_func_exec, 0);

    unsigned fn_act_priv = ++fn_exec_last;
    actfuncs[PRIV_ACTID] = fn_act_priv;
    OTF_Writer_writeDefFunction(writer, 0, fn_act_priv, "Priv Activity", grp_func_exec, 0);
    unsigned fn_act_idle = ++fn_exec_last;
    actfuncs[IDLE_ACTID] = fn_act_idle;
    OTF_Writer_writeDefFunction(writer, 0, fn_act_idle, "Idle Activity", grp_func_exec, 0);

    printf("writing OTF events\n");

    uint64_t timestamp = 0;

    std::unordered_map<TileId, bool> awake;
    std::unordered_map<TileId, bool> cur_act;

    for(const std::pair<TileId, State> s : states) {
        awake[s.first] = true;
        cur_act[s.first] = fn_act_priv;
        OTF_Writer_writeEnter(writer, timestamp, fn_act_priv, s.first.raw(), 0);
    }

    // finally loop over events and write OTF
    for(auto event = trace_buf.begin(); event != trace_buf.end(); ++event) {
        // don't use the same timestamp twice
        if(event->timestamp <= timestamp)
            event->timestamp = timestamp + 1;

        timestamp = event->timestamp;

        if(verbose)
            std::cout << *event << "\n";

        switch(event->type) {
            case EVENT_MSG_SEND_START:
                OTF_Writer_writeSendMsg(writer, timestamp, event->tile.raw(), event->remote.raw(),
                                        grp_msg, event->tag, event->size, 0);
                ++stats.send;
                break;

            case EVENT_MSG_RECV:
                OTF_Writer_writeRecvMsg(writer, timestamp, event->tile.raw(), event->remote.raw(),
                                        grp_msg, event->tag, event->size, 0);
                ++stats.recv;
                break;

            case EVENT_MSG_SEND_DONE: break;

            case EVENT_MEM_READ_START:
                OTF_Writer_writeSendMsg(writer, timestamp, event->tile.raw(), event->remote.raw(),
                                        grp_mem, event->tag, event->size, 0);
                ++stats.read;
                break;

            case EVENT_MEM_READ_DONE:
                OTF_Writer_writeRecvMsg(writer, timestamp, event->remote.raw(), event->tile.raw(),
                                        grp_mem, event->tag, event->size, 0);
                ++stats.finish;
                break;

            case EVENT_MEM_WRITE_START:
                OTF_Writer_writeSendMsg(writer, timestamp, event->tile.raw(), event->remote.raw(),
                                        grp_mem, event->tag, event->size, 0);
                ++stats.write;
                break;

            case EVENT_MEM_WRITE_DONE:
                OTF_Writer_writeRecvMsg(writer, timestamp, event->remote.raw(), event->tile.raw(),
                                        grp_mem, event->tag, event->size, 0);
                ++stats.finish;
                break;

            case EVENT_WAKEUP:
                if(!awake[event->tile]) {
                    OTF_Writer_writeLeave(writer, timestamp - 1, fn_exec_sleep, event->tile.raw(),
                                          0);
                    OTF_Writer_writeEnter(writer, timestamp, cur_act[event->tile],
                                          event->tile.raw(), 0);
                    awake[event->tile] = true;
                }
                break;

            case EVENT_SUSPEND:
                if(awake[event->tile]) {
                    OTF_Writer_writeLeave(writer, timestamp - 1, cur_act[event->tile],
                                          event->tile.raw(), 0);
                    OTF_Writer_writeEnter(writer, timestamp, fn_exec_sleep, event->tile.raw(), 0);
                    awake[event->tile] = false;
                }
                break;

            case EVENT_SET_ACTID: {
                auto fn = actfuncs.find(event->tag);
                if(fn == actfuncs.end()) {
                    char name[16];
                    snprintf(name, sizeof(name), "ACT_%#x", (unsigned)event->tag);
                    actfuncs[event->tag] = ++fn_exec_last;
                    OTF_Writer_writeDefFunction(writer, 0, actfuncs[event->tag], name,
                                                grp_func_exec, 0);
                    fn = actfuncs.find(event->tag);
                }

                if(awake[event->tile] && cur_act[event->tile] != fn->second) {
                    OTF_Writer_writeLeave(writer, timestamp - 1, cur_act[event->tile],
                                          event->tile.raw(), 0);
                    OTF_Writer_writeEnter(writer, timestamp, fn->second, event->tile.raw(), 0);
                }

                cur_act[event->tile] = fn->second;
                break;
            }
        }

        ++stats.total;
    }

    for(const std::pair<TileId, State> s : states) {
        if(awake[s.first])
            OTF_Writer_writeLeave(writer, timestamp, cur_act[s.first], s.first.raw(), 0);
        else
            OTF_Writer_writeLeave(writer, timestamp, fn_exec_sleep, s.first.raw(), 0);
    }
}

static void gen_act_events(OTF_Writer *writer, Stats &stats, std::vector<Event> &trace_buf,
                           std::unordered_map<TileId, State> &states, uint32_t binary_count,
                           char **binaries) {
    // Processes
    std::set<unsigned> actIds;

    OTF_Writer_writeDefProcess(writer, 0, PRIV_ACTID, "Priv Activity", 0);
    OTF_Writer_assignProcess(writer, PRIV_ACTID, 1);
    actIds.insert(PRIV_ACTID);
    actIds.insert(IDLE_ACTID);

    for(auto ev = trace_buf.begin(); ev != trace_buf.end(); ++ev) {
        if(ev->type == EVENT_SET_ACTID && actIds.find(ev->tag) == actIds.end()) {
            char actName[8];
            snprintf(actName, sizeof(actName), "Act%u", (unsigned)ev->tag);
            OTF_Writer_writeDefProcess(writer, 0, ev->tag, actName, 0);
            OTF_Writer_assignProcess(writer, ev->tag, 1);
            actIds.insert(ev->tag);
        }
    }

    // Process groups
    size_t i = 0;
    uint32_t allActs[actIds.size()];
    for(auto it = actIds.begin(); it != actIds.end(); ++it, ++i)
        allActs[i] = *it;

    unsigned grp_mem = (1 << 20) + 1;
    OTF_Writer_writeDefProcessGroup(writer, 0, grp_mem, "Memory Read/Write", actIds.size(),
                                    allActs);
    unsigned grp_msg = (1 << 20) + 2;
    OTF_Writer_writeDefProcessGroup(writer, 0, grp_msg, "Message Send/Receive", actIds.size(),
                                    allActs);

    // Function groups
    unsigned grp_func_count = 0;
    unsigned grp_func_exec = grp_func_count++;
    OTF_Writer_writeDefFunctionGroup(writer, 0, grp_func_exec, "Execution");
    unsigned grp_func_mem = grp_func_count++;
    OTF_Writer_writeDefFunctionGroup(writer, 0, grp_func_mem, "Memory");
    unsigned grp_func_msg = grp_func_count++;
    OTF_Writer_writeDefFunctionGroup(writer, 0, grp_func_msg, "Messaging");
    unsigned grp_func_user = grp_func_count++;
    OTF_Writer_writeDefFunctionGroup(writer, 0, grp_func_user, "User");

    for(uint32_t i = 0; i < binary_count; ++i)
        OTF_Writer_writeDefFunctionGroup(writer, 0, grp_func_count + i, binaries[i]);

    // Execution functions
    unsigned fn_exec_last = (2 << 20) + 0;
    std::map<unsigned, unsigned> actfuncs;

    unsigned fn_exec_sleep = ++fn_exec_last;
    OTF_Writer_writeDefFunction(writer, 0, fn_exec_sleep, "Sleeping", grp_func_exec, 0);
    unsigned fn_exec_running = ++fn_exec_last;
    OTF_Writer_writeDefFunction(writer, 0, fn_exec_running, "Running", grp_func_exec, 0);

    // Message functions
    unsigned fn_msg_send = (3 << 20) + 1;
    OTF_Writer_writeDefFunction(writer, 0, fn_msg_send, "msg_send", grp_func_msg, 0);

    // Memory Functions
    unsigned fn_mem_read = (3 << 20) + 2;
    OTF_Writer_writeDefFunction(writer, 0, fn_mem_read, "mem_read", grp_func_mem, 0);
    unsigned fn_mem_write = (3 << 20) + 3;
    OTF_Writer_writeDefFunction(writer, 0, fn_mem_write, "mem_write", grp_func_mem, 0);

    printf("writing OTF events\n");

    std::unordered_map<unsigned, bool> awake;
    std::unordered_map<TileId, unsigned> cur_act;

    for(const std::pair<TileId, State> s : states)
        cur_act[s.first] = PRIV_ACTID;

    uint32_t ufunc_max_id = (3 << 20);
    std::map<std::pair<int, std::string>, uint32_t> ufunc_map;

    uint32_t func_start_id = (4 << 20);

    // function call stack per activity
    std::array<uint, GEM5_MAX_ACTS> func_stack;
    func_stack.fill(0);
    std::array<uint, GEM5_MAX_ACTS> ufunc_stack;
    ufunc_stack.fill(0);

    uint64_t timestamp = 0;

    for(auto it = actIds.begin(); it != actIds.end(); ++it) {
        awake[*it] = false;
        OTF_Writer_writeEnter(writer, timestamp, fn_exec_sleep, *it, 0);
    }

    // finally loop over events and write OTF
    for(auto event = trace_buf.begin(); event != trace_buf.end(); ++event) {
        // don't use the same timestamp twice
        if(event->timestamp <= timestamp)
            event->timestamp = timestamp + 1;

        timestamp = event->timestamp;
        unsigned act = cur_act[event->tile];
        unsigned remote_act = cur_act[event->remote];

        if(verbose) {
            TileId tile = event->tile;
            TileId remote = event->remote;
            event->tile = TileId(0xFFFF, act);
            event->remote = TileId(0xFFFF, remote_act);
            std::cout << tile << ": " << *event << "\n";
            event->tile = tile;
            event->remote = remote;
        }

        switch(event->type) {
            case EVENT_MSG_SEND_START:
                // TODO currently, we don't display that as functions, because it interferes with
                // the UFUNCs.
                // OTF_Writer_writeEnter(writer, timestamp, fn_msg_send, act, 0);
                OTF_Writer_writeSendMsg(writer, timestamp, act, remote_act, grp_msg, event->tag,
                                        event->size, 0);
                ++stats.send;
                break;

            case EVENT_MSG_RECV:
                OTF_Writer_writeRecvMsg(writer, timestamp, act, remote_act, grp_msg, event->tag,
                                        event->size, 0);
                ++stats.recv;
                break;

            case EVENT_MSG_SEND_DONE:
                // OTF_Writer_writeLeave(writer, timestamp, fn_msg_send, act, 0);
                break;

            case EVENT_MEM_READ_START:
                // OTF_Writer_writeEnter(writer, timestamp, fn_mem_read, act, 0);
                OTF_Writer_writeSendMsg(writer, timestamp, act, remote_act, grp_mem, event->tag,
                                        event->size, 0);
                ++stats.read;
                break;

            case EVENT_MEM_READ_DONE:
                // OTF_Writer_writeLeave(writer, timestamp, fn_mem_read, act, 0);
                OTF_Writer_writeRecvMsg(writer, timestamp, remote_act, act, grp_mem, event->tag,
                                        event->size, 0);
                ++stats.finish;
                break;

            case EVENT_MEM_WRITE_START:
                // OTF_Writer_writeEnter(writer, timestamp, fn_mem_write, act, 0);
                OTF_Writer_writeSendMsg(writer, timestamp, act, remote_act, grp_mem, event->tag,
                                        event->size, 0);
                ++stats.write;
                break;

            case EVENT_MEM_WRITE_DONE:
                if(stats.read || stats.write) {
                    // OTF_Writer_writeLeave(writer, timestamp, fn_mem_write, act, 0);
                    OTF_Writer_writeRecvMsg(writer, timestamp, remote_act, act, grp_mem, event->tag,
                                            event->size, 0);
                    ++stats.finish;
                }
                break;

            case EVENT_WAKEUP:
                if(!awake[act]) {
                    OTF_Writer_writeLeave(writer, timestamp - 1, fn_exec_sleep, act, 0);
                    OTF_Writer_writeEnter(writer, timestamp, fn_exec_running, act, 0);
                    awake[act] = true;
                }
                break;

            case EVENT_SUSPEND:
                if(awake[act]) {
                    OTF_Writer_writeLeave(writer, timestamp - 1, fn_exec_running, act, 0);
                    OTF_Writer_writeEnter(writer, timestamp, fn_exec_sleep, act, 0);
                    awake[act] = false;
                }
                break;

            case EVENT_SET_ACTID: {
                if(awake[act]) {
                    OTF_Writer_writeLeave(writer, timestamp - 1, fn_exec_running, act, 0);
                    OTF_Writer_writeEnter(writer, timestamp, fn_exec_sleep, act, 0);
                    awake[act] = false;
                }

                cur_act[event->tile] = event->tag;
                break;
            }

            case EVENT_UFUNC_ENTER: {
                auto ufunc_map_iter = ufunc_map.find(std::make_pair(event->bin, event->name));
                uint32_t id = 0;
                if(ufunc_map_iter == ufunc_map.end()) {
                    id = (++ufunc_max_id);
                    ufunc_map.insert(std::make_pair(std::make_pair(event->bin, event->name), id));
                    unsigned group = grp_func_user;
                    if(event->bin != static_cast<uint32_t>(-1))
                        group = grp_func_count + event->bin;
                    OTF_Writer_writeDefFunction(writer, 0, id, event->name, group, 0);
                }
                else
                    id = ufunc_map_iter->second;
                ++(ufunc_stack[act]);
                OTF_Writer_writeEnter(writer, timestamp, id, act, 0);
                ++stats.ufunc_enter;
            } break;

            case EVENT_UFUNC_EXIT: {
                if(ufunc_stack[act] < 1) {
                    std::cout << act << " WARNING: exit at ufunc stack level " << ufunc_stack[act]
                              << " dropped.\n";
                    ++stats.warnings;
                }
                else {
                    --(ufunc_stack[act]);
                    OTF_Writer_writeLeave(writer, timestamp, 0, act, 0);
                }
                ++stats.ufunc_exit;
            } break;

            case EVENT_FUNC_ENTER: {
                uint32_t id = event->tag;
                ++(func_stack[act]);
                OTF_Writer_writeEnter(writer, timestamp, func_start_id + id, act, 0);
                ++stats.func_enter;
            } break;

            case EVENT_FUNC_EXIT: {
                if(func_stack[act] < 1) {
                    std::cout << act << " WARNING: exit at func stack level " << func_stack[act]
                              << " dropped.\n";
                    ++stats.warnings;
                }
                else {
                    --(func_stack[act]);
                    OTF_Writer_writeLeave(writer, timestamp, 0, act, 0);
                }
                ++stats.func_exit;
            } break;
        }

        ++stats.total;
    }

    for(auto it = actIds.begin(); it != actIds.end(); ++it) {
        if(awake[*it])
            OTF_Writer_writeLeave(writer, timestamp, fn_exec_running, *it, 0);
        else
            OTF_Writer_writeLeave(writer, timestamp, fn_exec_sleep, *it, 0);
    }
}

static void usage(const char *name) {
    fprintf(stderr, "Usage: %s [-v] (tiles|acts) <file> [<binary>...]\n", name);
    fprintf(stderr, "  -v:            be verbose\n");
    fprintf(stderr, "  (tiles|acts):    the mode\n");
    fprintf(stderr, "  <file>:        the gem5 log file\n");
    fprintf(stderr, "  [<binary>...]: optionally a list of binaries for profiling\n");
    fprintf(stderr, "\n");
    fprintf(stderr,
            "The 'tiles' mode generates a tile-centric trace, i.e., the tiles are the processes");
    fprintf(stderr,
            " and it is shown at which points in time which Activity was running on which tile.\n");
    fprintf(
        stderr,
        "The 'acts' mode generates a Activity-centric trace, i.e., the activities are the processes");
    fprintf(stderr, " and it is shown what they do.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "The following gem5 log flags (M3_GEM5_LOG) are used:\n");
    fprintf(stderr, " - Tcu,TcuCmd    for messages and memory reads/writes\n");
    fprintf(stderr, " - TcuConnector  for suspend/wakeup\n");
    fprintf(stderr, " - TcuRegWrite   for the running Activity\n");
    fprintf(stderr, " - Exec,ExecPC   for profiling (only in 'acts' mode)\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    if(argc < 3)
        usage(argv[0]);

    int argstart = 1;
    Mode mode = MODE_TILES;
    if(strcmp(argv[1], "-v") == 0) {
        verbose = 1;
        argstart++;
    }

    if(strcmp(argv[argstart], "tiles") == 0)
        mode = MODE_TILES;
    else if(strcmp(argv[argstart], "acts") == 0)
        mode = MODE_ACTS;
    else
        usage(argv[0]);

    if(mode == MODE_ACTS) {
        for(int i = argstart + 2; i < argc; ++i)
            syms.addFile(argv[i]);
    }

    std::vector<Event> trace_buf;

    std::unordered_map<TileId, State> states = read_trace_file(argv[argstart + 1], mode, trace_buf);

    // now sort the trace buffer according to timestamps
    printf("sorting %zu events\n", trace_buf.size());

    std::sort(trace_buf.begin(), trace_buf.end(), [](const Event &a, const Event &b) {
        return a.timestamp < b.timestamp;
    });

    // Declare a file manager and a writer.
    OTF_FileManager *manager;
    OTF_Writer *writer;

    // Initialize the file manager. Open at most 100 OS files.
    manager = OTF_FileManager_open(100);
    assert(manager);

    // Initialize the writer.
    writer = OTF_Writer_open("trace", 1, manager);
    assert(writer);

    // Write some important Definition Records.
    // Timer res. in ticks per second
    OTF_Writer_writeDefTimerResolution(writer, 0, GEM5_TICKS_PER_SEC);

    Stats stats;

    if(mode == MODE_TILES)
        gen_pe_events(writer, stats, trace_buf, states);
    else {
        gen_act_events(writer, stats, trace_buf, states,
                       static_cast<uint32_t>(argc - (argstart + 2)), argv + argstart + 2);
    }

    if(stats.send != stats.recv) {
        printf("WARNING: #send != #recv\n");
        ++stats.warnings;
    }
    if(stats.read + stats.write != stats.finish) {
        printf("WARNING: #read+#write != #finish\n");
        ++stats.warnings;
    }
    if(stats.func_enter != stats.func_exit) {
        printf("WARNING: #func_enter != #func_exit\n");
        ++stats.warnings;
    }
    if(stats.ufunc_enter != stats.ufunc_exit) {
        printf("WARNING: #ufunc_enter != #ufunc_exit\n");
        ++stats.warnings;
    }

    printf("total events: %u\n", stats.total);
    printf("warnings: %u\n", stats.warnings);
    printf("send: %u\n", stats.send);
    printf("recv: %u\n", stats.recv);
    printf("read: %u\n", stats.read);
    printf("write: %u\n", stats.write);
    printf("finish: %u\n", stats.finish);
    printf("func_enter: %u\n", stats.func_enter);
    printf("func_exit: %u\n", stats.func_exit);
    printf("ufunc_enter: %u\n", stats.ufunc_enter);
    printf("ufunc_exit: %u\n", stats.ufunc_exit);

    // Clean up before exiting the program.
    OTF_Writer_close(writer);
    OTF_FileManager_close(manager);

    return 0;
}
