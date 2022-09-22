#!/bin/bash

usage() {
    echo "Usage: $1 <script> [--debug=<prog>]" 1>&2
    exit 1
}

if [ "$1" = "-h" ] || [ "$1" = "--help" ] || [ "$1" = "-?" ]; then
    usage "$0"
fi

build=build/$M3_TARGET-$M3_ISA-$M3_BUILD
bindir=$build/bin
hwssh=${M3_HW_SSH:-syn}

if [ $# -lt 1 ]; then
    usage "$0"
fi
script=$1
shift

debug=""
for p in "$@"; do
    case $p in
        --debug=*)
            debug=${p#--debug=}
            ;;
    esac
done

if [ "$M3_FS" = "" ]; then
    M3_FS="default.img"
fi
export M3_FS

if [ "$M3_HDD" = "" ]; then
    M3_HDD_PATH="build/$M3_TARGET-$M3_ISA-$M3_BUILD/disk.img"
else
    M3_HDD_PATH=$M3_HDD
fi

generate_config() {
    if [ ! -f "$1" ]; then
        echo "error: '$1' is not a file" >&2 && exit 1
    fi

    hd=$M3_HDD_PATH
    fs=build/$M3_TARGET-$M3_ISA-$M3_BUILD/$M3_FS
    fssize=$(stat --format="%s" "$fs")
    sed "
        s#\$fs.path#$fs#g;
        s#\$fs.size#$fssize#g;
        s#\$hd.path#$hd#g;
    " < "$1" > "$2/boot-all.xml"

    xmllint --schema misc/boot.xsd --noout "$2/boot-all.xml" > /dev/null || exit 1
    # this can fail if there is no app element (e.g., standalone.xml)
    xmllint --xpath /config/dom/app "$2/boot-all.xml" > "$2/boot.xml" || true
}

build_params_gem5() {
    generate_config "$1" "$M3_OUT" || exit 1

    kargs=$(perl -ne 'printf("'"$bindir"/'%s,", $1) if /<kernel\s.*args="(.*?)"/' < "$M3_OUT/boot-all.xml")
    mods=$(perl -ne 'printf(",'"$bindir"'/%s", $1) if /app\s.*args="([^\/"\s]+).*"/' < "$M3_OUT/boot-all.xml")
    mods="$M3_OUT/boot.xml$mods"

    if [ "$M3_GEM5_DBG" = "" ]; then
        M3_GEM5_DBG="Tcu"
    fi
    if [ "$M3_GEM5_CPU" = "" ]; then
        if [ "$debug" != "" ]; then
            M3_GEM5_CPU="TimingSimpleCPU"
        else
            M3_GEM5_CPU="DerivO3CPU"
        fi
    fi

    M3_CORES=3

    cmd=$kargs
    c=$(echo -n "$cmd" | sed 's/[^,]//g' | wc -c)
    while [ "$c" -lt "$M3_CORES" ]; do
        cmd="$cmd$bindir/tilemux,"
        c=$((c + 1))
    done

    if [[ $mods == *disk* ]] && [ "$M3_HDD" = "" ]; then
        ./src/tools/disk.py create "$M3_HDD_PATH" "$build/$M3_FS"
    fi

    M3_GEM5_CPUFREQ=${M3_GEM5_CPUFREQ:-1GHz}
    M3_GEM5_MEMFREQ=${M3_GEM5_MEMFREQ:-333MHz}
    export M3_GEM5_TILES=$M3_CORES
    export M3_GEM5_FS=/home/op/ba/bench-lx/build/riscv64/disks/bench.img
    export M3_GEM5_IDE_DRIVE=$M3_HDD_PATH

    params=$(mktemp)
    trap 'rm -f $params' EXIT ERR INT TERM

    {
        echo -n "--outdir=$M3_OUT --debug-file=gem5.log --debug-flags=$M3_GEM5_DBG"
        if [ "$M3_GEM5_PAUSE" != "" ]; then
            echo -n " --listener-mode=on"
        fi
        if [ "$M3_GEM5_DBGSTART" != "" ]; then
            echo -n " --debug-start=$M3_GEM5_DBGSTART"
        fi
        echo -n " config/linux.py --cpu-type $M3_GEM5_CPU --isa $M3_ISA"
        echo -n " --cmd \"$bindir/kernel\" --mods \"$mods\""
        echo -n " --cpu-clock=$M3_GEM5_CPUFREQ --sys-clock=$M3_GEM5_MEMFREQ"
        if [ "$M3_GEM5_PAUSE" != "" ]; then
            echo -n " --pausetile=$M3_GEM5_PAUSE"
        fi
    } > "$params"

    if [ "$M3_ISA" = "x86_64" ]; then
        gem5build="X86"
    elif [ "$M3_ISA" = "arm" ]; then
        gem5build="ARM"
    elif [ "$M3_ISA" = "riscv" ]; then
        gem5build="RISCV"
    else
        echo "Unsupported ISA: $M3_ISA" >&2
        exit 1
    fi

    export M5_PATH=$build
    if [ "$DBG_GEM5" != "" ]; then
        tmp=$(mktemp)
        trap 'rm -f $tmp' EXIT ERR INT TERM
        {
            echo "b main"
            echo -n "run "
            cat "$params"
            echo
        } > "$tmp"
        gdb --tui platform/gem5/build/$gem5build/gem5.debug "--command=$tmp"
    else
        if [ "$debug" != "" ]; then
            xargs -a "$params" $build/tools/ignoreint platform/gem5/build/$gem5build/gem5.opt
        else
            xargs -a "$params" platform/gem5/build/$gem5build/gem5.opt
        fi
    fi
}

if [ "$M3_TARGET" = "gem5" ] || [ "$M3_RUN_GEM5" = "1" ]; then
    build_params_gem5 "$script"
else
    echo "Unknown target '$M3_TARGET'"
fi

# ensure that we get into cooked mode again
stty sane

if [ -f "$build/$M3_FS.out" ]; then
    "$build/tools/m3fsck" "$build/$M3_FS.out" && echo "FS image '$build/$M3_FS.out' is valid"
fi
