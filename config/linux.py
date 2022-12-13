import os, sys
from subprocess import call

sys.path.append(os.path.realpath('platform/gem5/configs/example'))
import tcu_fs as t

t.mod_offset = t.linux_tile_offset + t.linux_tile_size
t.tile_offset = t.mod_offset + t.mod_size

options = t.getOptions()
root = t.createRoot(options)

num_eps = 192
mem_tile_no = 2

kernel_tile = t. createCoreTile(noc=root.noc,
                             options=options,
                             no=0,
                             cmdline='build/gem5-riscv-release/bin/kernel -l', # FIXME
                             memTile=mem_tile_no,
                             l1size='32kB',
                             l2size='256kB',
                             epCount=num_eps)

linux_tile = t.createLinuxTile(options,
                             noc=root.noc,
                             no=1,
                             memTile=mem_tile_no,
                             kernel=options.kernel,
                             fsImage=options.disk_image,
                             commandLine='earlycon=sbi console=ttyS0 root=/dev/vda1')

memory_tile = t.createMemTile(noc=root.noc,
                            options=options,
                            no=mem_tile_no,
                            size='3072MB',
                            image=None,
                            imageNum=0,
                            epCount=num_eps)

t.runSimulation(root, options, [kernel_tile, linux_tile, memory_tile])
