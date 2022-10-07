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

# fsimg = os.environ.get('M3_GEM5_FS')
# assert(os.path.isfile(fsimg))
# fsimgnum = os.environ.get('M3_GEM5_FSNUM', '1')


# disk image
# hard_disk0 = os.environ.get('M3_GEM5_IDE_DRIVE')
# assert(os.path.isfile(hard_disk0))

tiles = []
linux_tile = createOSTile(noc=root.noc,
                          options=options,
                          no=1,
                          kernel=bootloader,
                          clParams='earlycon=sbi console=ttyS0 root=/dev/vda1',
                          memTile=3,
                          l1size='32kB',
                          l2size='256kB',
                          tcupos=0,
                          epCount=num_eps)

tiles.append(linux_tile)


tile = createSerialTile(noc=root.noc,
                        options=options,
                        no=2,
                        memTile=3,
                        epCount=num_eps)
tiles.append(tile)

# tile = createStorageTile(noc=root.noc,
#                             options=options,
#                             no=2,
#                             memTile=3,
#                             img0=None,
#                             epCount=num_eps)
# tiles.append(tile)


tile = createMemTile(noc=root.noc,
                        options=options,
                        no=3,
                        size='3072MB',
                        image=None,
                        imageNum=0,
                        epCount=num_eps)
tiles.append(tile)

runSimulation(root, options, tiles)