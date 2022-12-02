#!/bin/bash

bifpga=/dev/ttyUSB2
sensor=/dev/ttyUSB3

echo "Configure USB forwarding (Sensor <-> FPGA):"
echo "BI-FPGA at $bifpga"
stty -F $bifpga speed 115200 cs8 > /dev/null
echo "NCG sensor at $sensor"
stty -F $sensor speed 115200 cs8 > /dev/null

echo "Press CTRL+C to stop forwarding..."
trap 'kill %1' SIGINT
cat $bifpga > $sensor &
cat $sensor > $bifpga

echo
exit
