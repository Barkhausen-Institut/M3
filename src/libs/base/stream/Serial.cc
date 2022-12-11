/*
 * Copyright (C) 2015-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <base/stream/Serial.h>
#include <base/time/Instant.h>

#include <string.h>

namespace m3 {

const char *Serial::_colors[] = {"31", "32", "33", "34", "35", "36"};
Serial *Serial::_inst USED;

void Serial::init(const char *path, TileId tile) {
    if(_inst == nullptr)
        _inst = new Serial();

    size_t len = strlen(path);
    const char *name = path + len - 1;
    while(name > path && *name != '/')
        name--;
    if(name != path)
        name++;

    size_t i = 0;
    strcpy(_inst->_outbuf + i, "\e[0;");
    i += 4;
    ulong col = tile.raw() % ARRAY_SIZE(_colors);
    strcpy(_inst->_outbuf + i, _colors[col]);
    i += 2;
    _inst->_outbuf[i++] = 'm';
    _inst->_outbuf[i++] = '[';
    _inst->_outbuf[i++] = 'C';
    _inst->_outbuf[i++] = '0' + static_cast<int>(tile.chip());
    _inst->_outbuf[i++] = 'T';
    _inst->_outbuf[i++] = '0' + (tile.tile() / 10);
    _inst->_outbuf[i++] = '0' + (tile.tile() % 10);
    _inst->_outbuf[i++] = ':';
    size_t x = 0;
    for(; x < 8 && name[x]; ++x)
        _inst->_outbuf[i++] = name[x];
    for(; x < 8; ++x)
        _inst->_outbuf[i++] = ' ';
    _inst->_outbuf[i++] = '@';
    _inst->_time = i;
    _inst->_start = _inst->_outpos = i + 11 + 2;
}

void Serial::write(char c) {
    if(c == '\0')
        return;

    _outbuf[_outpos++] = c;
    if(_outpos == OUTBUF_SIZE - SUFFIX_LEN - 1) {
        _outbuf[_outpos++] = '\n';
        c = '\n';
    }
    if(c == '\n')
        flush();
}

void Serial::flush() {
    char tmp[14];
    OStringStream curtime(tmp, sizeof(tmp));
    format_to(curtime, "{: <11}] "_cf, (m3::TimeInstant::now().as_nanos() / 1000) % 10000000000);
    strncpy(_outbuf + _time, curtime.str(), curtime.length());
    strcpy(_outbuf + _outpos, "\e[0m");
    _outpos += SUFFIX_LEN;
    Machine::write(_outbuf, _outpos);
    // keep prefix
    _outpos = _start;
}

}
