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

rootfs = os.environ.get('M3_ROOTFS')
if rootfs is not None:
    print(os.getcwd())
    assert os.path.isfile(rootfs), f"$M3_ROOTFS ({rootfs}) is not a file"

mem_tile = 2

tiles = []
linux_tile = createOSTile(noc=root.noc,
                          options=options,
                          no=0,
                          kernel=bootloader,
                          clParams='earlycon=sbi console=ttyS0 root=/dev/vda1',
                          memTile=mem_tile,
                          l1size='32kB',
                          l2size='256kB',
                          tcupos=0,
                          epCount=num_eps)

tiles.append(linux_tile)


tile = createSerialTile(noc=root.noc,
                        options=options,
                        no=1,
                        memTile=mem_tile,
                        epCount=num_eps)
tiles.append(tile)


tile = createMemTile(noc=root.noc,
                        options=options,
                        no=2,
                        size='3072MB',
                        image=None,
                        imageNum=0,
                        epCount=num_eps)
tiles.append(tile)


if rootfs is not None:
    print(f"using {rootfs} as file system on a storage tile")
    tile = createStorageTile(noc=root.noc,
                            options=options,
                            no=3,
                            memTile=mem_tile,
                            img0=rootfs,
                            epCount=num_eps)
    tiles.append(tile)


runSimulation(root, options, tiles)