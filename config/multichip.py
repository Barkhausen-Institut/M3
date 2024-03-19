import os
import sys

sys.path.append(os.path.realpath('platform/gem5/configs/example'))  # NOQA
from tcu_fs import *

options = getOptions()
root = Root(full_system=True)

cmd_list = options.cmd.split(",")

num_mem = 1
num_tiles = int(os.environ.get('M3_GEM5_TILES'))
num_cores_per_chip = int(num_tiles / 2)
mem_tile = TileId(1, num_cores_per_chip)

# Create a top-level voltage domain
root.voltage_domain = VoltageDomain(voltage=options.sys_voltage)

# Create a source clock for the system and set the clock period
root.clk_domain = SrcClockDomain(clock=options.sys_clock,
                                 voltage_domain=root.voltage_domain)

# All tiles are connected to a NoC (Network on Chip). In this case it's just
# a simple XBar.
root.noc1 = IOXBar()
root.noc1.frontend_latency = 4
root.noc1.forward_latency = 2
root.noc1.response_latency = 4

root.noc2 = IOXBar()
root.noc2.frontend_latency = 4
root.noc2.forward_latency = 2
root.noc2.response_latency = 4

root.bridge12 = Bridge(delay='50ns')
root.bridge12.mem_side_port = root.noc2.cpu_side_ports
root.bridge12.cpu_side_port = root.noc1.default

root.bridge21 = Bridge(delay='50ns')
root.bridge21.mem_side_port = root.noc1.cpu_side_ports
root.bridge21.cpu_side_port = root.noc2.default

tiles = []

# create the core tiles
for i in range(0, num_cores_per_chip):
    tile = createCoreTile(noc=root.noc1,
                          options=options,
                          id=TileId(0, i),
                          cmdline=cmd_list[i],
                          memTile=mem_tile if cmd_list[i] != "" else None,
                          l1size='32kB',
                          l2size='256kB')
    tiles.append(tile)

# create tile for serial input (unless we're debugging gem5)
if int(os.environ.get("DBG_GEM5", 0)) != 1:
    tile = createSerialTile(noc=root.noc1,
                            options=options,
                            id=TileId(0, num_cores_per_chip),
                            memTile=None)
    tiles.append(tile)

for i in range(0, num_cores_per_chip):
    tile = createCoreTile(noc=root.noc2,
                          options=options,
                          id=TileId(1, i),
                          cmdline=cmd_list[num_cores_per_chip + i],
                          memTile=mem_tile if cmd_list[num_cores_per_chip + i] != "" else None,
                          l1size='32kB',
                          l2size='256kB')
    tiles.append(tile)

# create the memory tile
tile = createMemTile(noc=root.noc2,
                     options=options,
                     id=mem_tile,
                     size='3072MB')
tiles.append(tile)

runSimulation(root, options, tiles)
