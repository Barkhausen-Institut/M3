#!/bin/bash

# compiles and runs an M3 system with a kernel and one linux tile
help="$0 [--debug-flags=...] [--no-run] [--cpu-type=...] [--rebuild-bbl] [--rebuild-gem5]"

if [ "$M3_TARGET" != 'gem5' ]; then
    echo '$M3_TARGET other than gem5 is not supported' >&2
    exit 1
fi

if [ "$M3_ISA" != 'riscv' ]; then
    echo '$M3_ISA other than riscv is not supported' >&2
    exit 1
fi

if [ -z "$M3_BENCH_LX_DIR" ]; then
    echo '$M3_BENCH_LX_DIR not set' >&2
    exit 1
fi

gem5_executable=platform/gem5/build/RISCV/gem5.opt

# environment variables
M3_BUILD="${M3_BUILD:-release}"
M3_OUT="${M3_OUT:-run}"

# command line options
debug_flags=""
no_run=false
gem5_cpu="TimingSimpleCPU"

# directories
build=build/$M3_TARGET-$M3_ISA-$M3_BUILD/linux
buildroot_dir="$build/buildroot"
disks_dir="$build/disks"
linux_dir="$build/linux"
bbl_dir="$build/bbl"
m3_root=`pwd`

mkdir -p "$buildroot_dir" "$disks_dir" "$linux_dir" "$bbl_dir"

main() {
    # command line args
    for arg in "$@"; do
        case $arg in
            --debug-flags=*)
                debug_flags=${arg#--debug-flags=}
                ;;
            --no-run)
                no_run=true
                ;;
            --cpu-type=*)
                gem5_cpu=${arg#--cpu-type=}
                ;;
            --rebuild-bbl)
                echo "removing old bbl build"
                rm -rf "$bbl_dir"/*
                ;;
            --rebuild-gem5)
                echo "removing old gem5 build"
                rm -f "$gem5_executable"
                ;;
            --help|-h)
                echo "$help"
                exit 0
                ;;
            *)
                echo "unknown option: $arg" >&2
                echo $help
                exit 1
        esac
    done

    # gem5
    if [ ! -x "$gem5_executable" ]; then
        mk_gem5
    fi

    # buildroot
    if [ ! -f "$disks_dir/root.img" ]; then
        mk_buildroot
    fi

    # linux
    if [ ! -f "$linux_dir/vmlinux" ]; then
        mk_linux
        rm -f "$bbl_dir/bbl" # rebuild bbl if linux was rebuilt
    fi

    # bbl
    if [ ! -f "$bbl_dir/bbl" ]; then
        mk_bbl
    fi

    if [ "$no_run" = false ]; then
        run_gem5
    fi
}

mk_gem5() {
    ( cd platform/gem5 && scons build/RISCV/gem5.opt -j$(nproc) )
    if [ $? -ne 0 ]; then
        echo "gem5 compilation failed" >&2
        exit 1
    fi
}

mk_buildroot() {
    if [ ! -f $buildroot_dir/.config ]; then
        cp "$M3_BENCH_LX_DIR/configs/config-buildroot-riscv64" "$buildroot_dir/.config"
    fi

    ( cd "$M3_BENCH_LX_DIR/buildroot" && make "O=$m3_root/$buildroot_dir" -j$(nproc) )
    if [ $? -ne 0 ]; then
        echo "buildroot compilation failed" >&2
        exit 1
    fi

    rm -f "$disks_dir/root.img"
    platform/gem5/util/gem5img.py init "$disks_dir/root.img" 128
    tmp=`mktemp -d`
    platform/gem5/util/gem5img.py mount "$disks_dir/root.img" $tmp
    cpioimg=`readlink -f $buildroot_dir/images/rootfs.cpio`
    ( cd $tmp && sudo cpio -id < $cpioimg )
    platform/gem5/util/gem5img.py umount $tmp
    rmdir $tmp
}

mk_linux() {
    if [ ! -f "$linux_dir/.config" ]; then
        cp "$M3_BENCH_LX_DIR/configs/config-linux-riscv64" "$linux_dir/.config"
    fi

    ( 
        export PATH="$m3_root/$buildroot_dir/host/usr/bin:$PATH"
        export ARCH=riscv
        export CROSS_COMPILE=riscv64-linux-
        cd "$M3_BENCH_LX_DIR/linux" && make "O=$m3_root/$linux_dir" -j$(nproc)
    )
    if [ $? -ne 0 ]; then
        echo "linux compilation failed" >&2
        exit 1
    fi
}

mk_bbl() {
    (
        export PATH="$m3_root/$buildroot_dir/host/usr/bin:$PATH"
        cd "$bbl_dir" \
            && RISCV=$m3_root/$buildroot_dir/host "$M3_BENCH_LX_DIR/riscv-pk/configure" \
                --host=riscv64-linux \
                "--with-payload=$m3_root/$linux_dir/vmlinux" \
                --with-mem-start=0x80000000 \
            && CFLAGS=" -D__riscv_compressed=1" make -j$(nproc)
    )
    if [ $? -ne 0 ]; then
        echo "bbl/riscv-pk compilation failed" >&2
        exit 1
    fi
}

run_gem5() {
    "$gem5_executable" \
        "--outdir=$M3_OUT" \
        `if [ -n "$debug_flags" ]; then echo "--debug-flags=$debug_flags"; fi` \
        --debug-file=gem5.log \
        config/linux.py \
        --disk-image "$disks_dir/root.img" \
        --kernel "$bbl_dir/bbl" \
        --cpu-type "$gem5_cpu"
}

main "$@"