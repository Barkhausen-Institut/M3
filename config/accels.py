import os
import sys

sys.path.append(os.path.realpath('platform/gem5/configs/example'))  # NOQA
from tcu_fs import *

options = getOptions()
root = createRoot(options)

cmd_list = options.cmd.split(",")

num_mem = 1
num_tiles = int(os.environ.get('M3_GEM5_TILES'))
accs = ['indir', 'indir', 'indir', 'indir', 'copy', 'copy', 'copy', 'copy', 'rot13']
mem_tile = TileId(0, num_tiles + len(accs))

tiles = []

# create the core tiles
for i in range(0, num_tiles):
    tile = createCoreTile(noc=root.noc,
                          options=options,
                          id=TileId(0, i),
                          cmdline=cmd_list[i],
                          memTile=mem_tile if cmd_list[i] != "" else None,
                          l1size='32kB',
                          l2size='256kB')
    tiles.append(tile)

options.cpu_clock = '1GHz'

# create accelerator tiles
for i in range(0, len(accs)):
    tile = createAccelTile(noc=root.noc,
                           options=options,
                           id=TileId(0, num_tiles + i),
                           accel=accs[i],
                           memTile=None,
                           spmsize='32MB')
    tiles.append(tile)

# create the memory tiles
for i in range(0, num_mem):
    tile = createMemTile(noc=root.noc,
                         options=options,
                         id=TileId(0, num_tiles + len(accs) + i),
                         size='3072MB')
    tiles.append(tile)

# create tile for serial input (unless we're debugging gem5)
if int(os.environ.get("DBG_GEM5", 0)) != 1:
    tile = createSerialTile(noc=root.noc,
                            options=options,
                            id=TileId(0, num_tiles + len(accs) + num_mem),
                            memTile=None)
    tiles.append(tile)

runSimulation(root, options, tiles)
