import os
import sys

sys.path.append(os.path.realpath('platform/gem5/configs/example'))  # NOQA
from tcu_fs import *

options = getOptions()
root = createRoot(options)

cmd_list = options.cmd.split(",")

num_mem = 1
num_coreacc = 1
num_tiles = int(os.environ.get('M3_GEM5_TILES')) - 1
mem_tile = TileId(0, num_tiles + num_coreacc)

tiles = []

# create the core tiles
for i in range(0, num_tiles):
    tile = createCoreTile(noc=root.noc,
                          options=options,
                          id=TileId(0, i),
                          cmdline=cmd_list[i],
                          memTile=mem_tile if cmd_list[i] != "" else None,
                          spmsize='64MB')
    tiles.append(tile)

# create core+accel tiles
options.isa = 'riscv32' if options.isa == 'riscv64' else options.isa
for i in range(0, num_coreacc):
    tile = createCoreAccTile(noc=root.noc,
                             options=options,
                             id=TileId(0, num_tiles + i),
                             cmdline="",
                             memTile=None,
                             spmsize='64MB')
    tiles.append(tile)
options.isa = os.environ.get('M3_ISA')

# create the memory tiles
for i in range(0, num_mem):
    tile = createMemTile(noc=root.noc,
                         options=options,
                         id=TileId(0, num_tiles + num_coreacc + i),
                         size='3072MB')
    tiles.append(tile)

# create tile for serial input (unless we're debugging gem5)
if int(os.environ.get("DBG_GEM5", 0)) != 1:
    tile = createSerialTile(noc=root.noc,
                            options=options,
                            id=TileId(0, num_tiles + num_coreacc + num_mem),
                            memTile=None)
    tiles.append(tile)

runSimulation(root, options, tiles)
