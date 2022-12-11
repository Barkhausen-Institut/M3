import os, sys
from subprocess import call

sys.path.append(os.path.realpath('platform/gem5/configs/example'))
from tcu_fs import *

options = getOptions()
root = createRoot(options)

cmd_list = options.cmd.split(",")

num_eps = 128 if os.environ.get('M3_TARGET') == 'hw' else 192
num_mem = 1
num_sto = 1 # Number of tiles for IDE storage
num_tiles = int(os.environ.get('M3_GEM5_TILES'))
num_spm = 4 if num_tiles >= 4 else 4 - num_tiles

fsimg = os.environ.get('M3_GEM5_FS')
fsimgnum = os.environ.get('M3_GEM5_FSNUM', '1')

# disk image
hard_disk0 = os.environ.get('M3_GEM5_IDE_DRIVE')
if not os.path.isfile(hard_disk0):
    num_sto = 0

num_rot13 = 2
num_kecacc = 1
mem_tile = TileId(0, num_tiles + num_sto + 2 + num_rot13 + num_kecacc)

tiles = []

# create the core tiles
for i in range(0, num_tiles - num_spm):
    tile = createCoreTile(noc=root.noc,
                          options=options,
                          id=TileId(0, i),
                          cmdline=cmd_list[i],
                          memTile=mem_tile,
                          l1size='32kB',
                          l2size='256kB',
                          epCount=num_eps)
    tiles.append(tile)

for i in range(num_tiles - num_spm, num_tiles):
    tile = createCoreTile(noc=root.noc,
                          options=options,
                          id=TileId(0, i),
                          cmdline=cmd_list[i],
                          memTile=mem_tile,
                          spmsize='32MB',
                          epCount=num_eps)
    tiles.append(tile)

# create the persistent storage tiles
for i in range(0, num_sto):
    tile = createStorageTile(noc=root.noc,
                             options=options,
                             id=TileId(0, num_tiles + i),
                             memTile=mem_tile,
                             img0=hard_disk0,
                             epCount=num_eps)
    tiles.append(tile)

# create ether tiles
ether0 = createEtherTile(noc=root.noc,
                         options=options,
                         id=TileId(0, num_tiles + num_sto + 0),
                         memTile=mem_tile,
                         epCount=num_eps)
tiles.append(ether0)

ether1 = createEtherTile(noc=root.noc,
                         options=options,
                         id=TileId(0, num_tiles + num_sto + 1),
                         memTile=mem_tile,
                         epCount=num_eps)
tiles.append(ether1)

linkEthertiles(ether0, ether1)

for i in range(0, num_rot13):
    rpe = createAccelTile(noc=root.noc,
                          options=options,
                          id=TileId(0, num_tiles + num_sto + 2 + i),
                          accel='rot13',
                          memTile=mem_tile,
                          spmsize='32MB',
                          epCount=num_eps)
    tiles.append(rpe)

for i in range(0, num_kecacc):
    tile = createKecAccTile(noc=root.noc,
                            options=options,
                            id=TileId(0, num_tiles + num_sto + 2 + num_rot13 + i),
                            cmdline=cmd_list[1],  # FIXME
                            memTile=mem_tile,
                            spmsize='32MB',
                            epCount=num_eps)
    tiles.append(tile)

# create the memory tiles
for i in range(0, num_mem):
    tile = createMemTile(noc=root.noc,
                         options=options,
                         id=TileId(0, num_tiles + num_sto + 2 + num_rot13  + num_kecacc + i),
                         size='3072MB',
                         image=fsimg if i == 0 else None,
                         imageNum=int(fsimgnum),
                         epCount=num_eps)
    tiles.append(tile)

# create tile for serial input
tile = createSerialTile(noc=root.noc,
                        options=options,
                        id=TileId(0, num_tiles + num_sto + 2 + num_rot13 + num_kecacc + num_mem),
                        memTile=mem_tile,
                        epCount=num_eps)
tiles.append(tile)

runSimulation(root, options, tiles)
