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

#include <base/Common.h>
#include <base/util/Math.h>
#include <base/Config.h>
#include <base/Heap.h>

#include <m3/session/Pager.h>
#include <m3/session/ResMng.h>
#include <m3/stream/FStream.h>
#include <m3/pes/VPE.h>
#include <m3/vfs/GenericFile.h>
#include <m3/vfs/MountTable.h>

#include <memory>

namespace m3 {

extern "C" void *_start;
extern "C" void *_text_start;
extern "C" void *_text_end;
extern "C" void *_data_start;
extern "C" void *_bss_end;

void VPE::init_state() {
    _resmng.reset(new ResMng(env()->rmng_sel));

    // it's initially 0. make sure it's at least the first usable selector
    _next_sel = Math::max<uint64_t>(KIF::FIRST_FREE_SEL, env()->first_sel);
    _rbufcur = env()->rbuf_cur;
    _rbufend = env()->rbuf_end;
    _eps_start = env()->first_std_ep;
}

void VPE::init_fs() {
    if(env()->pager_sess)
        _pager = Reference<Pager>(new Pager(env()->pager_sess));
    _ms.reset(MountTable::unserialize(reinterpret_cast<const void*>(
        env()->mounts_addr), env()->mounts_len));
    _fds.reset(FileTable::unserialize(reinterpret_cast<const void*>(
        env()->fds_addr), env()->fds_len));
}

void VPE::reset() noexcept {
    // don't free the stuff of our parent
    _self_ptr->_fds.release();
    _self_ptr->_ms.release();

    _self_ptr = reinterpret_cast<VPE*>(env()->vpe_addr);
    _self_ptr->_pe->sel(KIF::SEL_PE);
    _self_ptr->_kmem->sel(KIF::SEL_KMEM);
    _self_ptr->sel(KIF::SEL_VPE);
    _self_ptr->_mem.sel(KIF::SEL_MEM);
    _self_ptr->epmng().reset();
    Gate::reset();
}

void VPE::run(void *lambda) {
    copy_sections();

    Env senv;
    senv.pe_id = 0;
    senv.pe_desc = _pe->desc().value();
    senv.argc = env()->argc;
    senv.argv = ENV_SPACE_START;
    senv.heap_size = env()->heap_size;

    senv.sp = CPU::get_sp();
    senv.entry = get_entry();
    senv.first_std_ep = _eps_start;
    senv.first_sel = 0;

    senv.lambda = reinterpret_cast<uintptr_t>(lambda);

    senv.rmng_sel = 0;
    senv.pager_sess = 0;
    senv.mounts_addr = 0;
    senv.mounts_len = 0;
    senv.fds_addr = 0;
    senv.fds_len = 0;

    senv.rbuf_cur = _rbufcur;
    senv.rbuf_end = _rbufend;

    senv.vpe_addr = reinterpret_cast<uint64_t>(this);
    senv.backend_addr = env()->backend_addr;

    /* write start env to PE */
    _mem.write(&senv, sizeof(senv), ENV_START);

    /* write args */
    std::unique_ptr<char[]> buffer(new char[BUF_SIZE]);
    size_t size = store_arguments(buffer.get(), static_cast<int>(env()->argc),
        reinterpret_cast<const char**>(env()->argv));
    _mem.write(buffer.get(), size, ENV_SPACE_START);

    /* go! */
    start();
}

void VPE::exec(int argc, const char **argv) {
    Env senv;
    std::unique_ptr<char[]> buffer(new char[BUF_SIZE]);

    _exec = std::make_unique<FStream>(argv[0], FILE_RWX);

    uintptr_t entry;
    size_t size;
    load(argc, argv, &entry, buffer.get(), &size);

    senv.pe_id = 0;
    senv.pe_desc = _pe->desc().value();
    senv.argc = static_cast<uint32_t>(argc);
    senv.argv = ENV_SPACE_START;
    senv.heap_size = _pager ? APP_HEAP_SIZE : 0;

    senv.sp = STACK_TOP;
    senv.entry = entry;
    senv.first_std_ep = _eps_start;
    senv.first_sel = _next_sel;

    senv.lambda = 0;

    senv.rmng_sel = _resmng->sel();
    senv.pager_sess = _pager ? _pager->sel() : 0;

    /* add mounts, fds, caps and eps */
    /* align it because we cannot necessarily read e.g. integers from unaligned addresses */
    size_t offset = Math::round_up(size, sizeof(word_t));

    senv.mounts_addr = ENV_SPACE_START + offset;
    senv.mounts_len = _ms->serialize(buffer.get() + offset, ENV_SPACE_SIZE - offset);
    offset = Math::round_up(offset + static_cast<size_t>(senv.mounts_len), sizeof(word_t));

    senv.fds_addr = ENV_SPACE_START + offset;
    senv.fds_len = _fds->serialize(buffer.get() + offset, ENV_SPACE_SIZE - offset);
    offset = Math::round_up(offset + static_cast<size_t>(senv.fds_len), sizeof(word_t));

    /* write entire runtime stuff */
    _mem.write(buffer.get(), offset, ENV_SPACE_START);

    senv.rbuf_cur = _rbufcur;
    senv.rbuf_end = _rbufend;

    senv.backend_addr = 0;
    senv.vpe_addr = 0;

    /* write start env to PE */
    _mem.write(&senv, sizeof(senv), ENV_START);

    /* go! */
    start();
}

void VPE::clear_mem(char *buffer, size_t count, uintptr_t dest) {
    memset(buffer, 0, BUF_SIZE);
    while(count > 0) {
        size_t amount = std::min(count, BUF_SIZE);
        _mem.write(buffer, amount, dest);
        count -= amount;
        dest += amount;
    }
}

void VPE::load_segment(ElfPh &pheader, char *buffer) {
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
            const GenericFile *rfile = static_cast<const GenericFile*>(_exec->file().get());
            _pager->map_ds(&virt, sz, prot, 0, rfile->sess(), pheader.p_offset);
            return;
        }

        assert(pheader.p_filesz == 0);
        _pager->map_anon(&virt, sz, prot, 0);
        return;
    }

    size_t segoff = pheader.p_vaddr;
    size_t count = pheader.p_filesz;
    /* the offset might be beyond EOF if count is 0 */
    if(count > 0) {
        /* seek to that offset and copy it to destination PE */
        size_t off = pheader.p_offset;
        if(_exec->seek(off, M3FS_SEEK_SET) != off)
            VTHROW(Errors::INVALID_ELF, "Unable to seek to segment at " << off);

        while(count > 0) {
            size_t amount = std::min(count, BUF_SIZE);
            if(_exec->read(buffer, amount) != amount)
                VTHROW(Errors::INVALID_ELF, "Unable to read " << amount << " bytes");

            _mem.write(buffer, amount, segoff);
            count -= amount;
            segoff += amount;
        }
    }

    /* zero the rest */
    clear_mem(buffer, pheader.p_memsz - pheader.p_filesz, segoff);
}

void VPE::load(int argc, const char **argv, uintptr_t *entry, char *buffer, size_t *size) {
    /* load and check ELF header */
    ElfEh header;
    if(_exec->read(&header, sizeof(header)) != sizeof(header))
        throw MessageException("Unable to read header", Errors::INVALID_ELF);

    if(header.e_ident[0] != '\x7F' || header.e_ident[1] != 'E' || header.e_ident[2] != 'L' ||
        header.e_ident[3] != 'F')
        throw MessageException("Invalid magic number", Errors::INVALID_ELF);

    /* copy load segments to destination PE */
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
        if(pheader.p_type != PT_LOAD || pheader.p_memsz == 0 || skip_section(&pheader))
            continue;

        load_segment(pheader, buffer);
        end = pheader.p_vaddr + pheader.p_memsz;
    }

    if(_pager) {
        // create area for stack
        goff_t virt = STACK_BOTTOM;
        _pager->map_anon(&virt, STACK_TOP - virt, Pager::READ | Pager::WRITE, Pager::MAP_UNINIT);

        // create heap
        virt = Math::round_up(end, static_cast<goff_t>(LPAGE_SIZE));
        _pager->map_anon(&virt, APP_HEAP_SIZE, Pager::READ | Pager::WRITE,
                         Pager::MAP_UNINIT | Pager::MAP_NOLPAGE);
    }

    *size = store_arguments(buffer, argc, argv);

    *entry = header.e_entry;
}

size_t VPE::store_arguments(char *buffer, int argc, const char **argv) {
    /* copy arguments and arg pointers to buffer */
    uint64_t *argptr = reinterpret_cast<uint64_t*>(buffer);
    char *args = buffer + static_cast<size_t>(argc) * sizeof(uint64_t);
    for(int i = 0; i < argc; ++i) {
        size_t len = strlen(argv[i]);
        if(args + len >= buffer + BUF_SIZE)
            throw Exception(Errors::INV_ARGS);
        strcpy(args, argv[i]);
        *argptr++ = ENV_SPACE_START + static_cast<size_t>(args - buffer);
        args += len + 1;
    }
    return static_cast<size_t>(args - buffer);
}

uintptr_t VPE::get_entry() {
    return reinterpret_cast<uintptr_t>(&_start);
}

void VPE::copy_sections() {
    goff_t start_addr, end_addr;

    if(_pager) {
        if(VPE::self().pager()) {
            _pager->clone();
            return;
        }

        // map text
        start_addr = reinterpret_cast<uintptr_t>(&_text_start);
        end_addr = reinterpret_cast<uintptr_t>(&_text_end);
        _pager->map_anon(&start_addr, end_addr - start_addr,
                         Pager::READ | Pager::WRITE | Pager::EXEC, Pager::MAP_UNINIT);

        // map data
        start_addr = reinterpret_cast<uintptr_t>(&_data_start);
        end_addr = Heap::end_area() + Heap::end_area_size();
        _pager->map_anon(&start_addr, end_addr - start_addr,
                         Pager::READ | Pager::WRITE, Pager::MAP_UNINIT | Pager::MAP_NOLPAGE);

        // map area for stack and boot/runtime stuff
        start_addr = ENV_START;
        _pager->map_anon(&start_addr, STACK_TOP - start_addr,
                         Pager::READ | Pager::WRITE, Pager::MAP_UNINIT);
    }

    /* copy text */
    start_addr = reinterpret_cast<uintptr_t>(&_text_start);
    end_addr = reinterpret_cast<uintptr_t>(&_text_end);
    _mem.write(reinterpret_cast<void*>(start_addr), end_addr - start_addr, start_addr);

    /* copy data and heap */
    start_addr = reinterpret_cast<uintptr_t>(&_data_start);
    end_addr = Heap::used_end();
    _mem.write(reinterpret_cast<void*>(start_addr), end_addr - start_addr, start_addr);

    /* copy end-area of heap */
    start_addr = Heap::end_area();
    _mem.write(reinterpret_cast<void*>(start_addr), Heap::end_area_size(), start_addr);

    /* copy stack */
    start_addr = CPU::get_sp();
    end_addr = STACK_TOP;
    _mem.write(reinterpret_cast<void*>(start_addr), end_addr - start_addr, start_addr);
}

bool VPE::skip_section(ElfPh *) {
    return false;
}

}
