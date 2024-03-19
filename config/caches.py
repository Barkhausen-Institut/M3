import os
import sys

sys.path.append(os.path.realpath('platform/gem5/configs/example'))  # NOQA
from tcu_fs import *

options = getOptions()
root = createRoot(options)

cmd_list = options.cmd.split(",")

num_mem = 1
num_tiles = int(os.environ.get('M3_GEM5_TILES'))
mem_tile = TileId(0, num_tiles)

# Memory watch example:
# options.mem_watches = {
#     TileId(0, 5) : [
#         AddrRange(0x0, 0x100000),
#         AddrRange(0xf0000000, 0xf0001000),
#     ],
# }

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

# create the memory tiles
for i in range(0, num_mem):
    tile = createMemTile(noc=root.noc,
                         options=options,
                         id=TileId(0, num_tiles + i),
                         size='3072MB')
    tiles.append(tile)

# create tile for serial input (unless we're debugging gem5)
if int(os.environ.get("DBG_GEM5", 0)) != 1:
    tile = createSerialTile(noc=root.noc,
                            options=options,
                            id=TileId(0, num_tiles + num_mem),
                            memTile=None)
    tiles.append(tile)

runSimulation(root, options, tiles)
