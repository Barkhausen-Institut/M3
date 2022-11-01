#!/bin/bash

## arch:
# sudo pacman -Syyu autoconf automake curl python3 libmpc mpfr gmp gawk base-devel bison flex texinfo gperf libtool patchutils bc zlib expat

## ubuntu:
# sudo apt-get install autoconf automake autotools-dev curl python3 libmpc-dev libmpfr-dev libgmp-dev gawk build-essential bison flex texinfo gperf libtool patchutils bc zlib1g-dev libexpat-dev

set -e

version="2022.10.11"
cross_root=$(dirname "$(readlink -f "$0")")
build="$(readlink -f "$cross_root/..")/build/riscv-linux-toolchain"
mkdir -p "$build"

tmpd=`mktemp -d`

(
    cd "$tmpd"
    git clone https://github.com/riscv/riscv-gnu-toolchain
    cd riscv-gnu-toolchain
    git checkout $version
    git submodule update --init musl

    export PATH="$build/bin:$PATH"
    ./configure --prefix="$build"
    make musl
)

rm -rf "$tmpd"

echo "cross compile binaries can be found in $build/bin"