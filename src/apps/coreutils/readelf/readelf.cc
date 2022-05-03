/*
 * Copyright (C) 2015-2018 Nils Asmussen <nils@os.inf.tu-dresden.de>
 * Economic rights: Technische Universitaet Dresden (Germany)
 *
 * Copyright (C) 2019 Nils Asmussen, Barkhausen Institut
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
#include <base/ELF.h>

#include <m3/stream/FStream.h>
#include <m3/stream/Standard.h>
#include <m3/vfs/VFS.h>

using namespace m3;

alignas(64) static char buffer[4096];

static const char *phtypes[] = {"NULL   ", "LOAD   ", "DYNAMIC", "INTERP ",
                                "NOTE   ", "SHLIB  ", "PHDR   ", "TLS    "};

template<typename ELF_EH, typename ELF_PH>
static void parse(FStream &bin) {
    bin.seek(0, M3FS_SEEK_SET);

    ELF_EH header;
    if(bin.read(&header, sizeof(header)) != sizeof(header))
        exitmsg("Invalid ELF-file");

    cout << "Program Headers:\n";
    cout << "  Type    Offset     VirtAddr     PhysAddr     FileSiz   MemSiz    Flg Align\n";

    size_t off = header.e_phoff;
    for(uint i = 0; i < header.e_phnum; ++i, off += header.e_phentsize) {
        ELF_PH pheader;
        if(bin.seek(off, M3FS_SEEK_SET) != off)
            exitmsg("Invalid ELF-file");
        if(bin.read(&pheader, sizeof(pheader)) != sizeof(pheader))
            exitmsg("Invalid ELF-file");

        cout << "  " << (pheader.p_type < ARRAY_SIZE(phtypes) ? phtypes[pheader.p_type] : "???????")
             << " " << fmt(pheader.p_offset, "#0x", 8) << " " << fmt(pheader.p_vaddr, "#0x", 10)
             << " " << fmt(pheader.p_paddr, "#0x", 10) << " " << fmt(pheader.p_filesz, "#0x", 7)
             << " " << fmt(pheader.p_memsz, "#0x", 7) << " "
             << ((pheader.p_flags & PF_R) ? "R" : " ") << ((pheader.p_flags & PF_W) ? "W" : " ")
             << ((pheader.p_flags & PF_X) ? "E" : " ") << " " << fmt(pheader.p_align, "#0x")
             << "\n";

        if(bin.seek(pheader.p_offset, M3FS_SEEK_SET) != pheader.p_offset)
            exitmsg("Invalid ELF-file");

        size_t count = pheader.p_filesz;
        while(count > 0) {
            size_t amount = std::min(count, sizeof(buffer));
            if(bin.read(buffer, amount) != static_cast<ssize_t>(amount))
                exitmsg("Reading failed");

            count -= amount;
        }
    }
}

int main(int argc, char **argv) {
    if(argc < 2)
        exitmsg("Usage: " << argv[0] << " <bin>");

    FStream bin(argv[1], FILE_R);

    /* load and check ELF header */
    ElfEh header;
    if(bin.read(&header, sizeof(header)) != sizeof(header))
        exitmsg("Invalid ELF-file");

    if(header.e_ident[0] != '\x7F' || header.e_ident[1] != 'E' || header.e_ident[2] != 'L' ||
       header.e_ident[3] != 'F')
        exitmsg("Invalid ELF-file");

    if(header.e_ident[EI_CLASS] == ELFCLASS32)
        parse<Elf32_Ehdr, Elf32_Phdr>(bin);
    else
        parse<Elf64_Ehdr, Elf64_Phdr>(bin);
    return 0;
}
