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

#pragma once

#include <m3/tiles/Activity.h>

#include <algorithm>
#include <vector>

namespace m3 {

class FileTable;
class MountTable;
class ChildActivity;
class ResMng;
class FStream;

class ActivityArgs {
    friend class ChildActivity;

public:
    explicit ActivityArgs() noexcept;

    ActivityArgs &pager(Reference<Pager> pager) noexcept;
    ActivityArgs &resmng(ResMng *resmng) noexcept {
        _rmng = resmng;
        return *this;
    }
    ActivityArgs &kmem(Reference<KMem> kmem) noexcept {
        _kmem = kmem;
        return *this;
    }

private:
    ResMng *_rmng;
    Reference<Pager> _pager;
    Reference<KMem> _kmem;
};

/**
 * Represents a child activity.
 *
 * This abstraction can be used to create new activities on a tile, exchange capabilities and data
 * with the activity and start it afterwards.
 */
class ChildActivity : public Activity {
    friend class FileTable;
    friend class MountTable;

    static const size_t BUF_SIZE;

public:
    /**
     * Creates a new child activity with given arguments.
     *
     * @param tile the tile to start the activity on
     * @param name the activity name (for debugging purposes)
     * @param args additional arguments to control the creation
     */
    explicit ChildActivity(const Reference<class Tile> &tile, const String &name,
                           const ActivityArgs &args = ActivityArgs());
    virtual ~ChildActivity();

    /**
     * @return the resource manager selector
     */
    capsel_t resmng_sel() const noexcept;

    /**
     * @return our file descriptor that will be installed for the given <child_fd>
     */
    fd_t get_file(fd_t child_fd);

    /**
     * Installs file <our_fd> as <child_fd> in this child activity.
     *
     * Files that are added to child activities are automatically delegated to the child upon
     * ChildActivity::run and ChildActivity::exec.
     *
     * @param child_fd the child's file descriptor to set
     * @oaram our_fd our file descriptor to install for the child
     */
    void add_file(fd_t child_fd, fd_t our_fd) {
        auto el = get_file_mapping(child_fd);
        if(el == _files.end())
            _files.push_back(std::make_pair(child_fd, our_fd));
        else
            el->second = our_fd;
    }

    /**
     * Installs mount <our_path> as <child_path> in this child activity.
     *
     * Mounts that are added to child activities are automatically delegated to the child upon
     * ChildActivity::run and ChildActivity::exec.
     *
     * @param child_path the child's path to install the mount at
     * @oaram our_path our path to the mount to pass to the child
     */
    void add_mount(const String &child_path, const String &our_path) {
        auto el = std::find_if(_mounts.begin(), _mounts.end(),
            [child_path](std::pair<String, String> &p) {
               return p.first == child_path;
            }
        );
        if(el == _mounts.end())
            _mounts.push_back(std::make_pair(child_path, our_path));
        else
            el->second = our_path;
    }

    /**
     * Returns a marshaller for the activity-local data.
     *
     * The marshaller overwrites the activity-local data and will be transmitted to the activity when calling
     * Activity::run or Activity::exec.
     *
     * @return a marshaller to write to the activity-local data
     */
    Marshaller data_sink() noexcept {
        return Marshaller(_data, sizeof(_data));
    }

    /**
     * Delegates the given object capability to this activity.
     *
     * @param sel the selector
     */
    void delegate_obj(capsel_t sel) {
        delegate(KIF::CapRngDesc(KIF::CapRngDesc::OBJ, sel));
    }

    /**
     * Delegates the given range of capabilities to this activity. They are put at the same selectors.
     *
     * @param crd the capabilities of your to activity to delegate to this activity
     */
    void delegate(const KIF::CapRngDesc &crd) {
        delegate(crd, crd.start());
    }

    /**
     * Delegates the given range of capabilities to this activity at position <dest>.
     *
     * @param crd the capabilities of your to activity to delegate to this activity
     * @param dest the destination in this activity
     */
    void delegate(const KIF::CapRngDesc &crd, capsel_t dest);

    /**
     * Obtains the given range of capabilities from this activity to your activity. The selectors are
     * automatically chosen.
     *
     * @param crd the capabilities of this activity to delegate to your activity
     */
    void obtain(const KIF::CapRngDesc &crd);

    /**
     * Obtains the given range of capabilities from this activity to your activity at position <dest>.
     *
     * @param crd the capabilities of this activity to delegate to your activity
     * @param dest the destination in your activity
     */
    void obtain(const KIF::CapRngDesc &crd, capsel_t dest);

    /**
     * Starts the activity, i.e., prepares the tile for execution and wakes it up.
     */
    void start();

    /**
     * Stops the activity, i.e., if it is running, the execution is stopped.
     */
    void stop();

    /**
     * Waits until the currently executing program on this activity is finished
     *
     * @return the exitcode
     */
    int wait();

    /**
     * Starts to wait until the currently executing program on this activity is finished, but tells
     * to kernel to notify us asynchronously via upcall.
     *
     * @param event the event for the upcall
     * @return 0 on success
     */
    int wait_async(event_t event);

    /**
     * Executes the given program with this activity.
     *
     * @param argc the number of arguments to pass to the program
     * @param argv the arguments to pass (argv[0] is the executable)
     */
    void exec(int argc, const char **argv);

    /**
     * Executes the program of Activity::own() (argv[0]) with this activity and calls the given
     * function instead of main.
     *
     * This has a few requirements/limitations:
     * 1. the current binary has to be stored in a file system
     * 2. this file system needs to be mounted, such that argv[0] is the current binary
     *
     * @param func the function to execute
     */
    void run(int (*func)());

private:
    std::vector<std::pair<fd_t, fd_t>>::iterator get_file_mapping(fd_t child_fd) {
        return std::find_if(_files.begin(), _files.end(),
            [child_fd](std::pair<fd_t, fd_t> &p) {
                return p.first == child_fd;
            }
        );
    }

    void do_exec(int argc, const char **argv, uintptr_t func_addr);
    void load_segment(ElfPh &pheader, char *buffer);
    size_t load(Env *env, int argc, const char **argv, char *buffer);
    void clear_mem(MemGate &mem, char *buffer, size_t count, uintptr_t dest);
    size_t serialize_state(Env &senv, char *buffer, size_t offset);
    size_t store_arguments(char *begin, char *buffer, int argc, const char *const *argv);

    uintptr_t get_entry();

    std::vector<std::pair<fd_t, fd_t>> _files;
    std::vector<std::pair<String, String>> _mounts;
    std::unique_ptr<FStream> _exec;
};

}
