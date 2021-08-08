/*
 * Copyright (C) 2016, Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <base/stream/Serial.h>
#include <string.h>

namespace m3 {

const char *Serial::_colors[] = {
    "31", "32", "33", "34", "35", "36"
};
Serial *Serial::_inst USED;

void Serial::init(const char *path, peid_t pe) {
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
    ulong col = pe % ARRAY_SIZE(_colors);
    strcpy(_inst->_outbuf + i, _colors[col]);
    i += 2;
    _inst->_outbuf[i++] = 'm';
    _inst->_outbuf[i++] = '[';
    _inst->_outbuf[i++] = 'P';
    _inst->_outbuf[i++] = 'E';
    _inst->_outbuf[i++] = pe <= 9 ? '0' + pe : 'A' + (pe - 10);
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

char Serial::read() {
    if(_inpos >= _inlen) {
        ssize_t res = Machine::read(_inbuf, INBUF_SIZE);
        if(res < 0)
            return 0;
        _inlen = static_cast<size_t>(res);
        _inpos = 0;
    }
    return _inbuf[_inpos++];
}

bool Serial::putback(char c) {
    if(_inpos == 0)
        return false;
    _inbuf[--_inpos] = c;
    return true;
}

void Serial::flush() {
    char tmp[14];
    OStringStream curtime(tmp, sizeof(tmp));
    curtime << m3::fmt((TCU::get().nanotime() / 1000) % 10000000000, 11) << "] ";
    strncpy(_outbuf + _time, curtime.str(), curtime.length());
    strcpy(_outbuf + _outpos, "\e[0m");
    _outpos += SUFFIX_LEN;
    Machine::write(_outbuf, _outpos);
    // keep prefix
    _outpos = _start;
}

}
