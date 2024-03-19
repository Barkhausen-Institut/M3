import os
import sys
from subprocess import call

sys.path.append(os.path.realpath('platform/gem5/configs/example'))  # NOQA
from tcu_fs import *

options = getOptions()
root = createRoot(options)

cmd_list = options.cmd.split(",")

num_mem = 1
num_sto = 1  # Number of tiles for IDE storage
num_tiles = int(os.environ.get('M3_GEM5_TILES'))

# disk image
hard_disk0 = os.environ.get('M3_GEM5_IDE_DRIVE')
if not os.path.isfile(hard_disk0):
    num_sto = 0

num_rot13 = 2
num_kecacc = 1
mem_tile = TileId(0, num_tiles + num_sto + 2 + num_rot13 + num_kecacc)

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

# create the persistent storage tiles
for i in range(0, num_sto):
    tile = createStorageTile(noc=root.noc,
                             options=options,
                             id=TileId(0, num_tiles + i),
                             memTile=None,
                             img0=hard_disk0)
    tiles.append(tile)

# create ether tiles
ether0 = createEtherTile(noc=root.noc,
                         options=options,
                         id=TileId(0, num_tiles + num_sto + 0),
                         memTile=None)
tiles.append(ether0)

ether1 = createEtherTile(noc=root.noc,
                         options=options,
                         id=TileId(0, num_tiles + num_sto + 1),
                         memTile=None)
tiles.append(ether1)

linkEthertiles(ether0, ether1)

for i in range(0, num_rot13):
    rpe = createAccelTile(noc=root.noc,
                          options=options,
                          id=TileId(0, num_tiles + num_sto + 2 + i),
                          accel='rot13',
                          memTile=None,
                          spmsize='32MB')
    tiles.append(rpe)

for i in range(0, num_kecacc):
    tile = createKecAccTile(noc=root.noc,
                            options=options,
                            id=TileId(0, num_tiles + num_sto + 2 + num_rot13 + i),
                            cmdline="",
                            memTile=None,
                            spmsize='64MB')
    tiles.append(tile)

# create the memory tiles
for i in range(0, num_mem):
    tile = createMemTile(noc=root.noc,
                         options=options,
                         id=TileId(0, num_tiles + num_sto + 2 + num_rot13 + num_kecacc + i),
                         size='3072MB')
    tiles.append(tile)

# create tile for serial input (unless we're debugging gem5)
if int(os.environ.get("DBG_GEM5", 0)) != 1:
    tile = createSerialTile(noc=root.noc,
                            options=options,
                            id=TileId(0, num_tiles + num_sto + 2 + num_rot13 + num_kecacc + num_mem),
                            memTile=None)
    tiles.append(tile)

runSimulation(root, options, tiles)
