/*
 * Copyright (C) 2020 Nils Asmussen, Barkhausen Institut
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

#include <byteswap.h>
#include <cstdio>
#include <elf.h>
#include <err.h>
#include <inttypes.h>

static constexpr size_t BYTES_PER_LINE = 8;

static void dumpSection(FILE *f, uint64_t paddr, Elf64_Off offset, uint64_t size) {
    fseek(f, static_cast<off_t>(offset), SEEK_SET);
    printf("@%08" PRIx64 "\n", paddr / BYTES_PER_LINE);
    while(size > 0) {
        uint64_t bytes = 0;
        size_t n = fread(&bytes, 1, sizeof(bytes), f);
        if(n == 0)
            break;

        printf("%016" PRIx64 "\n", bytes);
        if(n > size)
            size = 0;
        else
            size -= n;
    }
}

template<typename EH, typename PH>
void parse_elf(FILE *f) {
    EH hdr;
    if(fread(&hdr, sizeof(hdr), 1, f) != 1)
        err(1, "Unable to read ELF header");

    off_t off = static_cast<off_t>(hdr.e_phoff);
    for(unsigned i = 0; i < hdr.e_phnum; ++i, off += hdr.e_phentsize) {
        PH phdr;
        fseek(f, off, SEEK_SET);
        if(fread(&phdr, sizeof(phdr), 1, f) != 1)
            err(1, "Unable to read program header %u", i);

        if(phdr.p_type != PT_LOAD)
            continue;

        if(phdr.p_filesz > 0)
            dumpSection(f, phdr.p_paddr, phdr.p_offset, phdr.p_filesz);
        if(phdr.p_memsz > phdr.p_filesz)
            printf("z%08" PRIx64 ":%08" PRIx64 "\n",
                   (phdr.p_paddr + phdr.p_filesz) / BYTES_PER_LINE,
                   (phdr.p_memsz - phdr.p_filesz + BYTES_PER_LINE - 1) / BYTES_PER_LINE);
    }
}

int main(int argc, char **argv) {
    if(argc != 2)
        err(1, "Usage: %s <elf-binary>", argv[0]);

    FILE *f = fopen(argv[1], "r");
    if(!f)
        err(1, "Unable to open ELF file '%s'", argv[1]);

    Elf32_Ehdr hdr;
    if(fread(&hdr, sizeof(hdr), 1, f) != 1)
        err(1, "Unable to read ELF header");

    if(hdr.e_ident[0] != '\x7F' || hdr.e_ident[1] != 'E' || hdr.e_ident[2] != 'L' ||
       hdr.e_ident[3] != 'F')
        err(1, "Invalid ELF file: invalid magic number");

    if(fseek(f, 0, SEEK_SET) != 0)
        err(1, "Unable to seek to file beginning");
    if(hdr.e_ident[4] == 1)
        parse_elf<Elf32_Ehdr, Elf32_Phdr>(f);
    else
        parse_elf<Elf64_Ehdr, Elf64_Phdr>(f);

    fclose(f);
    return 0;
}
