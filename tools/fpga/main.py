#!/usr/bin/env python3

import argparse
import traceback
from time import sleep, time
import threading
import os
import sys

import fpga_top
from noc import NoCmonitor
from fpga_utils import FPGA_Error

import loader
import term


timeout_ev = threading.Event()
started_ev = threading.Event()


class TimeoutThread(threading.Thread):
    def __init__(self, timeout):
        super(TimeoutThread, self).__init__()
        self.daemon = True
        self.timeout = timeout
        self.start()

    def run(self):
        end = int(time()) + self.timeout
        while True:
            now = int(time())
            if now >= end:
                break
            sleep(end - now)
        print("Execution timed out after {} seconds".format(self.timeout))
        sys.stdout.flush()
        timeout_ev.set()
        if not started_ev.is_set():
            os._exit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fpga', type=int)
    parser.add_argument('--version', type=int)
    parser.add_argument('--reset', action='store_true')
    parser.add_argument('--debug', type=int)
    parser.add_argument('--tile', action='append')
    parser.add_argument('--mod', action='append')
    parser.add_argument('--vm', action='store_true')
    parser.add_argument('--serial')
    parser.add_argument('--logflags')
    parser.add_argument('--timeout', type=int)
    args = parser.parse_args()

    NoCmonitor()
    if args.timeout is not None:
        TimeoutThread(args.timeout)

    # connect to FPGA
    fpga_inst = fpga_top.FPGA_TOP(args.version, args.fpga, args.reset)

    # stop all tiles
    for tile in fpga_inst.pms:
        tile.stop()

    # check TCU versions
    for tile in fpga_inst.pms:
        tcu_version = tile.tcu_version()
        if tcu_version != args.version:
            print("Tile %s has TCU version %d, but expected %d" %
                  (tile.name, tcu_version, args.version))
            return

    mods = [] if args.mod is None else args.mod
    pmp_size = 16 * 1024 * 1024 if args.vm else 64 * 1024 * 1024

    ld = loader.Loader(pmp_size, args.vm)

    # disable NoC ARQ for program upload
    fpga_inst.set_arq_enable(False)

    ld.init(fpga_inst.pms, fpga_inst.dram1, args.tile, mods, args.logflags)

    # enable NoC ARQ when cores are running
    fpga_inst.set_arq_enable(True)

    ld.start(fpga_inst.pms, args.debug)

    # signal run.sh that everything has been loaded
    if args.debug is not None:
        ready = open('.ready', 'w')
        ready.write('1')
        ready.close()

    if args.serial is not None:
        terminal = term.LxTerm(args.serial)
    else:
        terminal = term.TCUTerm(fpga_inst.dram1, fpga_inst.nocif)

    # write in binary to stdout (we get individual bytes from Linux, for example)
    fdout = os.fdopen(sys.stdout.fileno(), "wb", closefd=False)

    # wait for prints
    started_ev.set()
    timed_out = False
    try:
        while True:
            # check for timeout
            if timeout_ev.is_set():
                timed_out = True
                break

            # check if there is input to pass to the FPGA
            if terminal.should_stop():
                # force-extract logs on ctrl+]
                timed_out = True
                break

            # check for output
            try:
                bytes = fpga_inst.nocif.receive_bytes(timeout_ns=10_000_000)
            except Exception:
                continue

            fdout.write(bytes)
            fdout.flush()

            # stop when we see the shutdown message from the M³ kernel
            try:
                msg = bytes.decode()
                if "Shutting down" in msg:
                    break
            except Exception:
                pass
    except KeyboardInterrupt:
        timed_out = True

    terminal.cleanup()

    # disable NoC ARQ again for post-processing
    fpga_inst.set_arq_enable(False)

    # stop all tiles
    print("Stopping all tiles...")
    for i, tile in enumerate(fpga_inst.pms, 0):
        try:
            dropped_packets = tile.nocarq.get_arq_drop_packet_count()
            total_packets = tile.nocarq.get_arq_packet_count()
            print("PM{}: NoC dropped/total packets: {}/{} ({:.0f}%)".format(i,
                  dropped_packets, total_packets, dropped_packets/total_packets*100))
        except Exception as e:
            print("PM{}: unable to read number of dropped NoC packets: {}".format(i, e))

        try:
            print("PM{}: TCU dropped/error flits: {}/{}".format(i,
                  tile.tcu_drop_flit_count(), tile.tcu_error_flit_count()))
        except Exception as e:
            print("PM{}: unable to read number of TCU dropped flits: {}".format(i, e))

        # extract TCU log on timeouts
        if timed_out:
            print("PM{}: reading TCU log...".format(i))
            sys.stdout.flush()
            try:
                tile.tcu_print_log('log/pm' + str(i) + '-tcu-cmds.log')
            except Exception as e:
                print("PM{}: unable to read TCU log: {}".format(i, e))
                print("PM{}: resetting TCU and reading all logs...".format(i))
                sys.stdout.flush()
                tile.tcu_reset()
                try:
                    tile.tcu_print_log('log/pm' + str(i) + '-tcu-cmds.log', all=True)
                except Exception:
                    pass

        # extract instruction trace
        try:
            tile.rocket_printTrace('log/pm' + str(i) + '-instrs.log')
        except Exception as e:
            print("PM{}: unable to read instruction trace: {}".format(i, e))
            print("PM{}: resetting TCU and reading all logs...".format(i))
            sys.stdout.flush()
            tile.tcu_reset()
            try:
                tile.rocket_printTrace('log/pm' + str(i) + '-instrs.log', all=True)
            except Exception:
                pass

        tile.stop()


try:
    main()
except FPGA_Error:
    sys.stdout.flush()
    traceback.print_exc()
except Exception:
    sys.stdout.flush()
    traceback.print_exc()
except KeyboardInterrupt:
    pass
