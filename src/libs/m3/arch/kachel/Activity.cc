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

#include <base/Common.h>
#include <base/util/Math.h>
#include <base/Config.h>
#include <base/mem/Heap.h>

#include <m3/EnvVars.h>
#include <m3/session/Pager.h>
#include <m3/session/ResMng.h>
#include <m3/stream/FStream.h>
#include <m3/tiles/Activity.h>
#include <m3/vfs/GenericFile.h>
#include <m3/vfs/MountTable.h>

#include <memory>

namespace m3 {

extern "C" void *_start;
extern "C" void *_text_start;
extern "C" void *_text_end;
extern "C" void *_data_start;
extern "C" void *_bss_end;

void OwnActivity::init_state() {
    _resmng.reset(new ResMng(env()->rmng_sel));

    // it's initially 0. make sure it's at least the first usable selector
    _next_sel = Math::max<uint64_t>(KIF::FIRST_FREE_SEL, env()->first_sel);
    _eps_start = env()->first_std_ep;
    _id = env()->act_id;
}

void OwnActivity::init_fs() {
    if(env()->pager_sess)
        _pager = Reference<Pager>(new Pager(env()->pager_sess, env()->pager_sgate));
    _ms.reset(MountTable::unserialize(reinterpret_cast<const void*>(
        env()->mounts_addr), env()->mounts_len));
    _fds.reset(FileTable::unserialize(reinterpret_cast<const void*>(
        env()->fds_addr), env()->fds_len));
    memcpy(_data, reinterpret_cast<const void*>(env()->data_addr), env()->data_len);
}

void ChildActivity::run(int (*func)()) {
    char **argv = reinterpret_cast<char**>(env()->argv);
    if(sizeof(char*) != sizeof(uint64_t)) {
        uint64_t *argv64 = reinterpret_cast<uint64_t*>(env()->argv);
        argv = new char*[env()->argc];
        for(uint64_t i = 0; i < env()->argc; ++i)
            argv[i] = reinterpret_cast<char*>(argv64[i]);
    }

    do_exec(env()->argc, const_cast<const char**>(argv), reinterpret_cast<uintptr_t>(func));

    if(sizeof(char*) != sizeof(uint64_t))
        delete[] argv;
}

void ChildActivity::do_exec(int argc, const char **argv, uintptr_t func_addr) {
    Env senv;
    std::unique_ptr<char[]> buffer(new char[BUF_SIZE]);

    Activity::own().files()->delegate(*this);
    Activity::own().mounts()->delegate(*this);

    // we need a new session to be able to get memory mappings
    _exec = std::make_unique<FStream>(argv[0], FILE_RWX | FILE_NEWSESS);

    size_t size = load(&senv, argc, argv, buffer.get());

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
    senv.mounts_len = Activity::own().mounts()->serialize(*this, buffer + offset, ENV_SPACE_SIZE - offset);
    offset = Math::round_up(offset + static_cast<size_t>(senv.mounts_len), sizeof(word_t));

    senv.fds_addr = ENV_SPACE_START + offset;
    senv.fds_len = Activity::own().files()->serialize(*this, buffer + offset, ENV_SPACE_SIZE - offset);
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
        size_t sz = Math::round_up(static_cast<size_t>(pheader.p_memsz),
                                   static_cast<size_t>(PAGE_SIZE));
        if(pheader.p_memsz == pheader.p_filesz) {
            _exec->file()->map(_pager, &virt, pheader.p_offset, sz, prot, 0);
            return;
        }

        assert(pheader.p_filesz == 0);
        _pager->map_anon(&virt, sz, prot, 0);
        return;
    }

    if(tile_desc().has_virtmem())
        VTHROW(Errors::NOT_SUP, "Exec with VM needs a pager");

    MemGate mem = get_mem(0, MEM_OFFSET + tile_desc().mem_size(), MemGate::W);

    size_t segoff = pheader.p_vaddr;
    size_t count = pheader.p_filesz;
    /* the offset might be beyond EOF if count is 0 */
    if(count > 0) {
        /* seek to that offset and copy it to destination tile */
        size_t off = pheader.p_offset;
        if(_exec->seek(off, M3FS_SEEK_SET) != off)
            VTHROW(Errors::INVALID_ELF, "Unable to seek to segment at " << off);

        while(count > 0) {
            size_t amount = std::min(count, BUF_SIZE);
            if(_exec->read(buffer, amount) != static_cast<ssize_t>(amount))
                VTHROW(Errors::INVALID_ELF, "Unable to read " << amount << " bytes");

            mem.write(buffer, amount, segoff);
            count -= amount;
            segoff += amount;
        }
    }

    /* zero the rest */
    clear_mem(mem, buffer, pheader.p_memsz - pheader.p_filesz, segoff);
}

size_t ChildActivity::load(Env *env, int argc, const char **argv, char *buffer) {
    /* load and check ELF header */
    ElfEh header;
    if(_exec->read(&header, sizeof(header)) != sizeof(header))
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
            VTHROW(Errors::INVALID_ELF, "Unable to seek to pheader at " << off);
        if(_exec->read(&pheader, sizeof(pheader)) != sizeof(pheader))
            VTHROW(Errors::INVALID_ELF, "Unable to read pheader at " << off);

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

    int var_count = static_cast<int>(EnvVars::count());
    if(var_count > 0) {
        env_size = Math::round_up(env_size, sizeof(uint64_t));
        char *env_buf = buffer + env_size;
        env->envp = ENV_SPACE_START + static_cast<size_t>(env_buf - buffer);
        env_size += store_arguments(buffer, env_buf, var_count, EnvVars::vars());
    }
    else
        env->envp = 0;

    env->entry = header.e_entry;
    return env_size;
}

size_t ChildActivity::store_arguments(char *begin, char *buffer, int argc, const char *const *argv) {
    /* copy arguments and arg pointers to buffer */
    uint64_t *argptr = reinterpret_cast<uint64_t*>(buffer);
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
