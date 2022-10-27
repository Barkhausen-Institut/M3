import os, sys
from subprocess import call

sys.path.append(os.path.realpath('platform/gem5/configs/example'))
from tcu_fs import *

options = getOptions()
root = createRoot(options)

num_eps = 192

bootloader = os.environ.get('M3_BOOTLOADER')
assert bootloader is not None, "$M3_BOOTLOADER not specified"
assert os.path.isfile(bootloader), "$M3_BOOTLOADER is not a file"

# rootfs = os.environ.get('M3_ROOTFS')
# if rootfs is not None:
#     assert os.path.isfile(rootfs), f"$M3_ROOTFS ({rootfs}) is not a file"

# mem_tile_no = 4

# kernel_tile = createCoreTile(noc=root.noc,
#                         options=options,
#                         no=0,
#                         cmdline="build/gem5-riscv-release/bin/kernel", # FIXME
#                         memTile=mem_tile_no,
#                         l1size='32kB',
#                         l2size='256kB',
#                         epCount=num_eps)
# tiles.append(kernel_tile)

# linux_tile = createOSTile(noc=root.noc,
#                           options=options,
#                           no=1,
#                           kernel=bootloader,
#                           clParams='earlycon=sbi console=ttyS0 root=/dev/vda1',
#                           memTile=mem_tile_no,
#                           l1size='32kB',
#                           l2size='256kB',
#                           epCount=num_eps)

# tiles.append(linux_tile)


# tile = createSerialTile(noc=root.noc,
#                         options=options,
#                         no=2,
#                         memTile=mem_tile_no,
#                         epCount=num_eps)
# tiles.append(tile)

# tile = createStorageTile(noc=root.noc,
#                         options=options,
#                         no=3,
#                         memTile=mem_tile_no,
#                         img0=rootfs,
#                         epCount=num_eps)
# tiles.append(tile)

# tile = createMemTile(noc=root.noc,
#                     options=options,
#                     no=mem_tile_no,
#                     size='3072MB',
#                     image=None,
#                     imageNum=0,
#                     epCount=num_eps)
# tiles.append(tile)

linux_tile = createOSTile2(options, noc=root.noc, memTile=1, kernel=bootloader)

memory_tile = createMemTile(noc=root.noc,
                            options=options,
                            no=1,
                            size='3072MB',
                            image=None,
                            imageNum=0,
                            epCount=num_eps)

runSimulation(root, options, [linux_tile, memory_tile])
