/*
 * Copyright (C) 2016-2018, Nils Asmussen <nils@os.inf.tu-dresden.de>
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

#include <base/Panic.h>
#include <base/WorkLoop.h>

#include <thread/ThreadManager.h>

namespace m3 {

void WorkLoop::thread_startup(void *) {
    WorkLoop *wl = env()->workloop();
    wl->run();

    wl->thread_shutdown();
}

void WorkLoop::thread_shutdown() {
    // first wait until we have no threads left that wait for some event
    ThreadManager &tm = ThreadManager::get();
    while(tm.get().blocked_count() > 0) {
        // we are not interested in the events here; just fetch them before the sleep
        DTU::get().fetch_events();

        DTU::get().try_sleep();

        tick();

        tm.yield();
    }

    tm.stop();

    PANIC("Should not get here");
}

void WorkLoop::add(WorkItem *item, bool permanent) {
    assert(_count < MAX_ITEMS);
    _items[_count++] = item;
    if(permanent)
        _permanents++;
}

void WorkLoop::remove(WorkItem *item) {
    for(size_t i = 0; i < MAX_ITEMS; ++i) {
        if(_items[i] == item) {
            _items[i] = nullptr;
            for(++i; i < MAX_ITEMS; ++i)
                _items[i - 1] = _items[i];
            _count--;
            break;
        }
    }
}

void WorkLoop::tick() {
    for(size_t i = 0; i < _count; ++i)
        _items[i]->work();
}

void WorkLoop::run() {
    while(has_items()) {
        // we are not interested in the events here; just fetch them before the sleep
        DTU::get().fetch_events();

        // wait first to ensure that we check for loop termination *before* going to sleep
        DTU::get().try_sleep();

        tick();

        m3::ThreadManager::get().yield();
    }
}

}
