#!/bin/bash

bifpga=/dev/ttyUSB2

echo "Run PuTTY to connect to UART on FPGA at $bifpga"
putty $bifpga -serial -sercfg 115200,8,n,1,N

exit
