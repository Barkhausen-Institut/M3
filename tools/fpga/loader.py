import os
import sys

from elftools.elf.elffile import ELFFile

import memory
import pm
from tcu import EP, MemEP, Flags, TCUExtReg
from tile import TileType

import utils

DRAM_SIZE = 2 * 1024 * 1024 * 1024
DRAM_OFF = 0x10000000
ENV = 0x10001000
MEM_TILE = 8

KENV_ADDR = 0
KENV_SIZE = 4 * 1024
SERIAL_ADDR = KENV_ADDR + KENV_SIZE
SERIAL_SIZE = 4 * 1024
PMP_ADDR = SERIAL_ADDR + SERIAL_SIZE


class Loader:
    def __init__(self, tcu_version: int, pmp_size: int, vm: bool):
        self.tcu_version = tcu_version
        self.pmp_size = pmp_size
        self.vm = vm

    def init(self, tiles: list[pm], dram: memory, kernels: list[str],
             mods: list[str], logflags: str):
        # load boot info into DRAM
        kernel_tiles = kernels[0:len(tiles)]
        if self.vm:
            mods_addr = PMP_ADDR + (len(kernel_tiles) * self.pmp_size)
        else:
            mods_addr = PMP_ADDR + (len(tiles) * self.pmp_size)
        self._load_boot_info(tiles, dram, mods, mods_addr)

        # init all tiles
        for i, tile in enumerate(tiles, 0):
            self._init_tile(dram, tile, i, i < len(kernel_tiles))

        # load kernels on tiles (only for Rocket cores)
        for i, pargs in enumerate(kernel_tiles, 0):
            if tiles[i].type == TileType.ROCKET:
                self._load_prog(tiles, dram, i, pargs.split(' '), logflags)

    def start(self, tiles: list[pm], debug: int):
        # start kernel tiles (only for Rocket cores)
        debug_tile = len(tiles) if debug is None else debug
        for i, tile in enumerate(tiles, 0):
            if tiles[i].type == TileType.ROCKET and i != debug_tile:
                # start core (via interrupt 0)
                tiles[i].inst.rocket_start()

    def _init_tile(self, dram: memory, tile: pm, tile_idx: int, loaded: bool):
        # reset TCU (clear command log and reset registers except FEATURES and EPs)
        tile.tcu_reset()

        # enable instruction trace for all Rocket tiles (doesn't cost anything)
        if tile.type == TileType.ROCKET:
            tile.inst.rocket_enableTrace()

        # set features: privileged, vm, ctxsw
        tile.tcu_set_features(1, self.vm, 1)

        # invalidate all EPs
        for ep in range(0, 127):
            tile.tcu_set_ep(ep, EP.invalid())

        # init PMP EP (for loaded tiles or if SPM should be emulated)
        if loaded or not self.vm:
            mem_begin = PMP_ADDR + tile_idx * self.pmp_size
            mem_size = self.pmp_size

            # install first PMP EP
            pmp_ep = MemEP()
            pmp_ep.set_chip(dram.nocid[0])
            pmp_ep.set_tile(dram.nocid[1])
            pmp_ep.set_act(0xFFFF)
            pmp_ep.set_flags(Flags.READ | Flags.WRITE)
            pmp_ep.set_addr(mem_begin)
            pmp_ep.set_size(mem_size)
            tile.tcu_set_ep(0, pmp_ep)

    def _load_boot_info(self, tiles: list[pm], dram: memory, mods: list[str], mods_addr: int):
        # boot info
        kenv_off = KENV_ADDR
        utils.write_u64(dram, kenv_off + 0 * 8, len(mods))    # mod_count
        utils.write_u64(dram, kenv_off + 1 * 8, len(tiles) + 1)  # tile_count
        utils.write_u64(dram, kenv_off + 2 * 8, 1)            # mem_count
        utils.write_u64(dram, kenv_off + 3 * 8, 0)            # serv_count
        kenv_off += 8 * 4

        # mods
        for m in mods:
            mod_size = self._add_mod(dram, mods_addr, m, kenv_off)
            mods_addr = (mods_addr + mod_size + 4096 - 1) & ~(4096 - 1)
            kenv_off += 80

        # tile descriptors
        for x in range(0, len(tiles)):
            utils.write_u64(dram, kenv_off, self._tile_desc(tiles, x))         # PM
            kenv_off += 8
        utils.write_u64(dram, kenv_off, self._tile_desc(tiles, len(tiles)))    # dram1
        kenv_off += 8

        # mems
        mem_start = mods_addr
        utils.write_u64(dram, kenv_off + 0, utils.glob_addr(MEM_TILE, mem_start))  # addr
        utils.write_u64(dram, kenv_off + 8, DRAM_SIZE - mem_start)          # size

    def _load_prog(self, tiles: list[pm], dram: memory, tile_idx: int,
                   args: list[str], logflags: str):
        pm = tiles[tile_idx]

        # start core
        pm.inst.start()

        print("%s: loading %s..." % (pm.name, args[0]))
        sys.stdout.flush()

        # verify entrypoint, because inject a jump instruction below that jumps to that address
        with open(args[0], 'rb') as f:
            elf = ELFFile(f)
            if elf.header['e_entry'] != 0x10003000:
                sys.exit("error: {} has entry {:#x}, not 0x10003000.".format(
                    args[0], elf.header['e_entry']))

        mem_begin = PMP_ADDR + tile_idx * self.pmp_size

        # load ELF file
        dram.mem.write_elf(args[0], mem_begin - DRAM_OFF)
        sys.stdout.flush()

        desc = self._tile_desc(tiles, tile_idx)
        kenv = utils.glob_addr(MEM_TILE, KENV_ADDR) if tile_idx == 0 else 0

        # write arguments and env vars
        argv = ENV + 0x400
        envp = self._write_args(dram, args, argv, mem_begin)
        if logflags:
            self._write_args(dram, ["LOG=" + logflags], envp, mem_begin)
        else:
            envp = 0

        # init environment
        dram_env = ENV + mem_begin - DRAM_OFF
        utils.write_u64(dram, dram_env - 0x1000, 0x0000306f)  # j _start (+0x3000)
        utils.write_u64(dram, dram_env + 0, 1)           # platform = HW
        utils.write_u64(dram, dram_env + 8, tile_idx)    # chip, tile
        utils.write_u64(dram, dram_env + 16, desc)       # tile_desc
        utils.write_u64(dram, dram_env + 24, len(args))  # argc
        utils.write_u64(dram, dram_env + 32, argv)       # argv
        utils.write_u64(dram, dram_env + 40, envp)       # envp
        utils.write_u64(dram, dram_env + 48, kenv)       # kenv
        utils.write_u64(dram, dram_env + 56, len(tiles) + 1)  # raw tile count
        # tile ids
        env_off = 64
        for tile in tiles:
            utils.write_u64(dram, dram_env + env_off, tile.nocid[0] << 8 | tile.nocid[1])
            env_off += 8
        utils.write_u64(dram, dram_env + env_off, dram.nocid[0] << 8 | dram.nocid[1])

        sys.stdout.flush()

    def _add_mod(self, dram: memory, addr: int, mod: str, offset: int) -> int:
        (name, path) = mod.split('=')
        path = os.path.basename(path)
        size = os.path.getsize(path)
        utils.write_u64(dram, offset + 0x0, utils.glob_addr(MEM_TILE, addr))
        utils.write_u64(dram, offset + 0x8, size)
        utils.write_str(dram, name, offset + 16)
        self._write_file(dram, path, addr)
        return size

    def _write_file(self, dram: memory, file: str, offset: int):
        print("%s: loading %s with %u bytes to %#x" %
              (dram.name, file, os.path.getsize(file), offset))
        sys.stdout.flush()

        with open(file, "rb") as f:
            content = f.read()
        dram.mem.write_bytes_checked(offset, content, True)

    def _write_args(self, dram: memory, args: list[str], argv: int, mem_begin: int) -> int:
        argc = len(args)
        args_addr = argv + (argc + 1) * 8
        for (idx, a) in enumerate(args, 0):
            # write pointer
            utils.write_u64(dram, argv + (mem_begin - DRAM_OFF) + idx * 8, args_addr)
            # write string
            utils.write_str(dram, a, args_addr + mem_begin - DRAM_OFF)
            args_addr += (len(a) + 1 + 7) & ~7
            if args_addr > ENV + 0x800:
                sys.exit("Not enough space for arguments")
        # null termination
        utils.write_u64(dram, argv + (mem_begin - DRAM_OFF) + argc * 8, 0)
        return args_addr

    def _tile_desc(self, tiles: list[pm], tile_idx: int):
        if tile_idx >= len(tiles):
            # mem size | TileAttr::IMEM | TileType::MEM
            return (DRAM_SIZE >> 12) << 28 | ((1 << 4) << 11) | 1

        tile = tiles[tile_idx]
        desc = tile.mem[tile.tcu.ext_reg_addr(TCUExtReg.TILE_DESC)]

        if not self.vm and (desc & ((1 << 4) << 11)) == 0:
            # mem size | TileAttr::IMEM
            desc |= ((self.pmp_size >> 12) << 28) | ((1 << 4) << 11)
        if self.tcu_version < 3:
            desc |= (1 << 5) << 11  # IEPS

        # TODO manually set RV32 until the HW reports that correctly
        if tile_idx == 3 or tile_idx == 4:
            desc &= ~(0x1FF << 6)
            desc |= 2 << 6

        return desc
