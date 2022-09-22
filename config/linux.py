import os, sys
from subprocess import call

sys.path.append(os.path.realpath('platform/gem5/configs/example'))
from tcu_fs import *

options = getOptions()
root = createRoot(options)

num_eps = 128 if os.environ.get('M3_TARGET') == 'hw' else 192
num_mem = 1
num_sto = 1 # Number of tiles for IDE storage
num_tiles = 2

fsimg = os.environ.get('M3_GEM5_FS')
if fsimg is None:
    print("M3_GEM5_FS env variable needed")
    exit(1)
fsimgnum = os.environ.get('M3_GEM5_FSNUM', '1')

# disk image
hard_disk0 = os.environ.get('M3_GEM5_IDE_DRIVE')
if not os.path.isfile(hard_disk0):
    num_sto = 0

num_rot13 = 2
num_kecacc = 1
mem_tile = num_tiles + num_sto + 2 + num_rot13 + num_kecacc + 1

tcupos = int(os.environ.get('M3_GEM5_TCUPOS', 0))

tiles = []

kernel_tile = createCoreTile(noc=root.noc,
                             options=options,
                             no=0,
                             cmdline=options.cmd,
                             memTile=mem_tile,
                             l1size='32kB',
                             l2size='256kB',
                             tcupos=tcupos,
                             epCount=num_eps)
tiles.append(kernel_tile)

linux_tile = createOSTile(noc=root.noc,
                          options=options,
                          no=1,
                          kernel='/home/op/ba/bench-lx/build/riscv64/riscv-pk/gem5/bbl',
                          clParams='earlycon=sbi console=ttyS0 root=/dev/vda1',
                          memTile=mem_tile,
                          l1size='32kB',
                          l2size='256kB',
                          tcupos=tcupos,
                          epCount=num_eps)

tiles.append(linux_tile)

# create the persistent storage tiles
for i in range(0, num_sto):
    tile = createStorageTile(noc=root.noc,
                             options=options,
                             no=num_tiles + i,
                             memTile=mem_tile,
                             img0=hard_disk0,
                             epCount=num_eps)
    tiles.append(tile)

# create ether tiles
ether0 = createEtherTile(noc=root.noc,
                         options=options,
                         no=num_tiles + num_sto + 0,
                         memTile=mem_tile,
                         epCount=num_eps)
tiles.append(ether0)

ether1 = createEtherTile(noc=root.noc,
                         options=options,
                         no=num_tiles + num_sto + 1,
                         memTile=mem_tile,
                         epCount=num_eps)
tiles.append(ether1)

linkEthertiles(ether0, ether1)

for i in range(0, num_rot13):
    rpe = createAccelTile(noc=root.noc,
                          options=options,
                          no=num_tiles + num_sto + 2 + i,
                          accel='rot13',
                          memTile=mem_tile,
                          spmsize='2MB',
                          epCount=num_eps)
    tiles.append(rpe)

for i in range(0, num_kecacc):
    tile = createKecAccTile(noc=root.noc,
                            options=options,
                            no=num_tiles + num_sto + 2 + num_rot13 + i,
                            cmdline='build/gem5-riscv-release/bin/tilemux',  # FIXME
                            memTile=mem_tile,
                            spmsize='32MB',
                            epCount=num_eps)
    tiles.append(tile)

# create tile for serial input
tile = createSerialTile(noc=root.noc,
                        options=options,
                        no=num_tiles + num_sto + 2 + num_rot13 + num_kecacc,
                        memTile=mem_tile,
                        epCount=num_eps)
tiles.append(tile)

# create the memory tiles
for i in range(0, num_mem):
    tile = createMemTile(noc=root.noc,
                         options=options,
                         no=num_tiles + num_sto + 2 + num_rot13  + num_kecacc + 1 + i,
                         size='3072MB',
                         image=fsimg if i == 0 else None,
                         imageNum=int(fsimgnum),
                         epCount=num_eps)
    tiles.append(tile)

runSimulation(root, options, tiles)
