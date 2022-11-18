import os, sys
from subprocess import call

sys.path.append(os.path.realpath('platform/gem5/configs/example'))
from tcu_fs import *

options = getOptions()
root = createRoot(options)

num_eps = 192

mem_tile_no = 3

kernel_tile = createCoreTile(noc=root.noc,
                             options=options,
                             no=0,
                             cmdline='build/gem5-riscv-release/bin/kernel', # FIXME
                             memTile=mem_tile_no,
                             l1size='32kB',
                             l2size='256kB',
                             epCount=num_eps)

root_tile = createCoreTile(noc=root.noc,
                             options=options,
                             no=1,
                             cmdline='build/gem5-riscv-release/bin/tilemux', # FIXME
                             memTile=mem_tile_no,
                             l1size='32kB',
                             l2size='256kB',
                             epCount=num_eps)

bench_tile = createCoreTile(noc=root.noc,
                             options=options,
                             no=2,
                             cmdline='build/gem5-riscv-release/bin/tilemux', # FIXME
                             memTile=mem_tile_no,
                             l1size='32kB',
                             l2size='256kB',
                             epCount=num_eps)

memory_tile = createMemTile(noc=root.noc,
                            options=options,
                            no=mem_tile_no,
                            size='3072MB',
                            image=None,
                            imageNum=0,
                            epCount=num_eps)

runSimulation(root, options, [kernel_tile, root_tile, bench_tile, memory_tile])
