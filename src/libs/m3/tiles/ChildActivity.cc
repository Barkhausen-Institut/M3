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

#include <m3/EnvVars.h>
#include <m3/Syscalls.h>
#include <m3/session/ResMng.h>
#include <m3/stream/FStream.h>
#include <m3/tiles/ChildActivity.h>
#include <m3/tiles/OwnActivity.h>
#include <m3/vfs/File.h>
#include <m3/vfs/FileTable.h>
#include <m3/vfs/MountTable.h>

namespace m3 {

extern "C" void *_start;

const size_t ChildActivity::BUF_SIZE = 4096;

ActivityArgs::ActivityArgs() noexcept : _rmng(nullptr), _pager(), _kmem() {
}

ActivityArgs &ActivityArgs::pager(Reference<Pager> pager) noexcept {
    _pager = pager;
    return *this;
}

ChildActivity::ChildActivity(const Reference<class Tile> &tile, const std::string_view &name,
                             const ActivityArgs &args)
    : Activity(Activity::own().alloc_sels(3), 0, tile,
               args._kmem ? args._kmem : Activity::own().kmem(), args._rmng),
      _files(),
      _mounts(),
      _exec() {
    // create pager first, to create session and obtain gate cap
    if(_tile->desc().has_virtmem()) {
        if(args._pager)
            _pager = args._pager;
        else if(Activity::own().pager())
            _pager = Activity::own().pager()->create_clone();
        // we need a pager on VM tiles
        else
            throw Exception(Errors::NOT_SUP);
    }

    if(_pager) {
        // now create activity, which implicitly obtains the gate cap from us
        const auto [eps_start, id] =
            Syscalls::create_activity(sel(), name, tile->sel(), _kmem->sel());
        _eps_start = eps_start;
        _id = id;
        // delegate activity cap to pager
        _pager->init(*this);
    }
    else {
        const auto [eps_start, id] =
            Syscalls::create_activity(sel(), name, tile->sel(), _kmem->sel());
        _eps_start = eps_start;
        _id = id;
    }
    _next_sel = Math::max(_kmem->sel() + 1, _next_sel);

    if(_resmng == nullptr) {
        capsel_t sgate_sel = alloc_sel();
        _resmng = Activity::own().resmng()->clone(*this, sgate_sel, name);
        // ensure that the child's cap space is not further ahead than ours
        // TODO improve that
        Activity::own()._next_sel = Math::max(_next_sel, Activity::own()._next_sel);
    }
    else
        delegate_obj(_resmng->sel());
}

ChildActivity::~ChildActivity() {
    try {
        stop();
    }
    catch(...) {
        // ignore
    }
}

fd_t ChildActivity::get_file(fd_t child_fd) {
    auto el = get_file_mapping(child_fd);
    if(el == _files.end())
        return FileTable::MAX_FDS;
    return el->second;
}

void ChildActivity::delegate(const KIF::CapRngDesc &crd, capsel_t dest) {
    Syscalls::exchange(sel(), crd, dest, false);
    _next_sel = Math::max(_next_sel, dest + crd.count());
}

void ChildActivity::obtain(const KIF::CapRngDesc &crd) {
    obtain(crd, Activity::own().alloc_sels(crd.count()));
}

void ChildActivity::obtain(const KIF::CapRngDesc &crd, capsel_t dest) {
    KIF::CapRngDesc own(crd.type(), dest, crd.count());
    Syscalls::exchange(sel(), own, crd.start(), true);
}

void ChildActivity::start() {
    Syscalls::activity_ctrl(sel(), KIF::Syscall::VCTRL_START, 0);
}

void ChildActivity::stop() {
    Syscalls::activity_ctrl(sel(), KIF::Syscall::VCTRL_STOP, 0);
}

int ChildActivity::wait_async(event_t event) {
    const capsel_t sels[] = {sel()};
    return Syscalls::activity_wait(sels, 1, event).first;
}

int ChildActivity::wait() {
    return wait_async(0);
}

void ChildActivity::exec(int argc, const char *const *argv, const char *const *envp) {
    do_exec(argc, argv, envp, 0);
}

void ChildActivity::run(int (*func)()) {
    char **argv = reinterpret_cast<char **>(env()->argv);
    if(sizeof(char *) != sizeof(uint64_t)) {
        uint64_t *argv64 = reinterpret_cast<uint64_t *>(env()->argv);
        argv = new char *[env()->argc];
        for(uint64_t i = 0; i < env()->argc; ++i)
            argv[i] = reinterpret_cast<char *>(argv64[i]);
    }

    do_exec(env()->argc, const_cast<const char **>(argv), nullptr,
            reinterpret_cast<uintptr_t>(func));

    if(sizeof(char *) != sizeof(uint64_t))
        delete[] argv;
}

void ChildActivity::do_exec(int argc, const char *const *argv, const char *const *envp,
                            uintptr_t func_addr) {
    Env senv;
    std::unique_ptr<char[]> buffer(new char[BUF_SIZE]);

    Activity::own().files()->delegate(*this);
    Activity::own().mounts()->delegate(*this);

    // we need a new session to be able to get memory mappings
    _exec = std::make_unique<FStream>(argv[0], FILE_RWX | FILE_NEWSESS);

    size_t size = load(&senv, argc, argv, envp, buffer.get());

    senv.platform = env()->platform;
    senv.tile_id = 0;
    senv.tile_desc = _tile->desc().value();
    senv.argc = static_cast<uint32_t>(argc);
    senv.argv = ENV_SPACE_START;
    senv.heap_size = _pager ? APP_HEAP_SIZE : 0;

    senv.sp = _tile->desc().stack_top();
    senv.first_std_ep = _eps_start;
    senv.first_sel = _next_sel;
    senv.act_id = _id;

    // copy tile ids unchanged to child
    senv.raw_tile_count = env()->raw_tile_count;
    for(size_t i = 0; i < senv.raw_tile_count; ++i)
        senv.raw_tile_ids[i] = env()->raw_tile_ids[i];

    senv.rmng_sel = _resmng->sel();
    senv.pager_sess = _pager ? _pager->sel() : 0;
    senv.pager_sgate = _pager ? _pager->child_sgate() : 0;

    senv.lambda = func_addr;

    /* add mounts, fds, caps and eps */
    /* align it because we cannot necessarily read e.g. integers from unaligned addresses */
    size_t env_size = Math::round_up(size, sizeof(word_t));
    env_size = serialize_state(senv, buffer.get(), env_size);

    goff_t env_page_off = ENV_START & ~PAGE_MASK;
    MemGate env_mem = get_mem(env_page_off, ENV_SIZE, MemGate::W);

    /* write entire runtime stuff */
    env_mem.write(buffer.get(), env_size, ENV_START + sizeof(senv) - env_page_off);

    /* write start env to tile */
    env_mem.write(&senv, sizeof(senv), ENV_START - env_page_off);

    /* go! */
    start();
}

size_t ChildActivity::serialize_state(Env &senv, char *buffer, size_t offset) {
    senv.mounts_addr = ENV_SPACE_START + offset;
    senv.mounts_len =
        Activity::own().mounts()->serialize(*this, buffer + offset, ENV_SPACE_SIZE - offset);
    offset = Math::round_up(offset + static_cast<size_t>(senv.mounts_len), sizeof(word_t));

    senv.fds_addr = ENV_SPACE_START + offset;
    senv.fds_len =
        Activity::own().files()->serialize(*this, buffer + offset, ENV_SPACE_SIZE - offset);
    offset = Math::round_up(offset + static_cast<size_t>(senv.fds_len), sizeof(word_t));

    senv.data_addr = ENV_SPACE_START + offset;
    senv.data_len = sizeof(_data);
    memcpy(buffer + offset, _data, sizeof(_data));
    offset = Math::round_up(offset + static_cast<size_t>(senv.data_len), sizeof(word_t));
    return offset;
}

void ChildActivity::clear_mem(MemGate &mem, char *buffer, size_t count, uintptr_t dest) {
    memset(buffer, 0, BUF_SIZE);
    while(count > 0) {
        size_t amount = std::min(count, BUF_SIZE);
        mem.write(buffer, amount, dest);
        count -= amount;
        dest += amount;
    }
}

void ChildActivity::load_segment(ElfPh &pheader, char *buffer) {
    if(_pager) {
        int prot = 0;
        if(pheader.p_flags & PF_R)
            prot |= Pager::READ;
        if(pheader.p_flags & PF_W)
            prot |= Pager::WRITE;
        if(pheader.p_flags & PF_X)
            prot |= Pager::EXEC;

        goff_t virt = pheader.p_vaddr;
        size_t sz =
            Math::round_up(static_cast<size_t>(pheader.p_memsz), static_cast<size_t>(PAGE_SIZE));
        if(pheader.p_memsz == pheader.p_filesz) {
            _exec->file()->map(_pager, &virt, pheader.p_offset, sz, prot, 0);
            return;
        }

        assert(pheader.p_filesz == 0);
        _pager->map_anon(&virt, sz, prot, 0);
        return;
    }

    if(tile_desc().has_virtmem())
        vthrow(Errors::NOT_SUP, "Exec with VM needs a pager"_cf);

    MemGate mem = get_mem(0, MEM_OFFSET + tile_desc().mem_size(), MemGate::W);

    size_t segoff = pheader.p_vaddr;
    size_t count = pheader.p_filesz;
    /* the offset might be beyond EOF if count is 0 */
    if(count > 0) {
        /* seek to that offset and copy it to destination tile */
        size_t off = pheader.p_offset;
        if(_exec->seek(off, M3FS_SEEK_SET) != off)
            vthrow(Errors::INVALID_ELF, "Unable to seek to segment at {}"_cf, off);

        while(count > 0) {
            size_t amount = std::min(count, BUF_SIZE);
            if(_exec->read(buffer, amount).unwrap() != amount)
                vthrow(Errors::INVALID_ELF, "Unable to read {} bytes"_cf, amount);

            mem.write(buffer, amount, segoff);
            count -= amount;
            segoff += amount;
        }
    }

    /* zero the rest */
    clear_mem(mem, buffer, pheader.p_memsz - pheader.p_filesz, segoff);
}

size_t ChildActivity::load(Env *env, int argc, const char *const *argv, const char *const *envp,
                           char *buffer) {
    /* load and check ELF header */
    ElfEh header;
    if(_exec->read(&header, sizeof(header)).unwrap() != sizeof(header))
        throw MessageException("Unable to read header", Errors::INVALID_ELF);

    if(header.e_ident[0] != '\x7F' || header.e_ident[1] != 'E' || header.e_ident[2] != 'L' ||
       header.e_ident[3] != 'F')
        throw MessageException("Invalid magic number", Errors::INVALID_ELF);

    /* copy load segments to destination tile */
    goff_t end = 0;
    size_t off = header.e_phoff;
    for(uint i = 0; i < header.e_phnum; ++i, off += header.e_phentsize) {
        /* load program header */
        ElfPh pheader;
        if(_exec->seek(off, M3FS_SEEK_SET) != off)
            vthrow(Errors::INVALID_ELF, "Unable to seek to pheader at {}"_cf, off);
        if(_exec->read(&pheader, sizeof(pheader)).unwrap() != sizeof(pheader))
            vthrow(Errors::INVALID_ELF, "Unable to read pheader at {}"_cf, off);

        /* we're only interested in non-empty load segments */
        if(pheader.p_type != PT_LOAD || pheader.p_memsz == 0)
            continue;

        load_segment(pheader, buffer);
        end = pheader.p_vaddr + pheader.p_memsz;
    }

    if(_pager) {
        // create area for stack
        auto stack_space = _tile->desc().stack_space();
        goff_t virt = stack_space.first;
        _pager->map_anon(&virt, stack_space.second, Pager::READ | Pager::WRITE, Pager::MAP_UNINIT);

        // create heap
        virt = Math::round_up(end, static_cast<goff_t>(PAGE_SIZE));
        _pager->map_anon(&virt, APP_HEAP_SIZE, Pager::READ | Pager::WRITE,
                         Pager::MAP_UNINIT | Pager::MAP_NOLPAGE);
    }

    size_t env_size = store_arguments(buffer, buffer, argc, argv);

    const char *const *envvars = envp ? envp : EnvVars::vars();
    int var_count = 0;
    const char *const *envvarsp = envvars;
    while(envvarsp && *envvarsp++)
        var_count++;

    if(var_count > 0) {
        env_size = Math::round_up(env_size, sizeof(uint64_t));
        char *env_buf = buffer + env_size;
        env->envp = ENV_SPACE_START + static_cast<size_t>(env_buf - buffer);
        env_size += store_arguments(buffer, env_buf, var_count, envvars);
    }
    else
        env->envp = 0;

    env->entry = header.e_entry;
    return env_size;
}

size_t ChildActivity::store_arguments(char *begin, char *buffer, int argc,
                                      const char *const *argv) {
    /* copy arguments and arg pointers to buffer */
    uint64_t *argptr = reinterpret_cast<uint64_t *>(buffer);
    char *args = buffer + static_cast<size_t>(argc + 1) * sizeof(uint64_t);
    for(int i = 0; i < argc; ++i) {
        size_t len = strlen(argv[i]);
        if(args + len >= buffer + BUF_SIZE)
            throw Exception(Errors::INV_ARGS);
        strcpy(args, argv[i]);
        *argptr++ = ENV_SPACE_START + static_cast<size_t>(args - begin);
        args += len + 1;
    }
    *argptr++ = 0;
    return static_cast<size_t>(args - buffer);
}

uintptr_t ChildActivity::get_entry() {
    return reinterpret_cast<uintptr_t>(&_start);
}

}
