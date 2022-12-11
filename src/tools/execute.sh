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

    # validate config
    xmllint --schema misc/boot.xsd --noout "$1" > /dev/null || exit 1

    # extract env variables and set them
    env=$(xmllint --xpath "/config/env/text()" "$1" 2>/dev/null)
    if [ "$env" != "" ]; then
        for e in $env; do
            # warn if the user has set it to a different value
            var=${e%%=*}
            val=${e#*=}
            old_env=$(env | grep "^$var=")
            old_val=${old_env#*=}
            if [ "$old_val" != "" ] && [ "$old_val" != "$val" ]; then
                echo "Warning: $var is already set to '$old_val', but overridden to '$val' by $1."
            fi
            export $e
        done
    fi

    # replace variables
    hd=$M3_HDD_PATH
    fs=build/$M3_TARGET-$M3_ISA-$M3_BUILD/$M3_FS
    fssize=$(stat --format="%s" "$fs")
    sed "
        s#\$fs.path#$fs#g;
        s#\$fs.size#$fssize#g;
        s#\$hd.path#$hd#g;
    " < "$1" > "$2/boot-all.xml"

    # extract runtime part; this can fail if there is no app element (e.g., standalone.xml)
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

    M3_CORES=${M3_CORES:-16}

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
    M3_GEM5_CFG=${M3_GEM5_CFG:-config/default.py}
    export M3_GEM5_TILES=$M3_CORES
    export M3_GEM5_FS=$build/$M3_FS
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
        echo -n " $M3_GEM5_CFG --cpu-type $M3_GEM5_CPU --isa $M3_ISA"
        echo -n " --cmd \"$cmd\" --mods \"$mods\""
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

    # remove all coverage files
    rm -rf $M3_OUT/coverage-*-*.profraw

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

build_params_hw() {
    generate_config "$1" "$M3_OUT" || exit 1

    kargs=$(perl -ne 'printf("%s;", $1) if /<kernel\s.*args="(.*?)"/' < "$M3_OUT/boot-all.xml")
    mods=$(perl -ne 'printf("%s;", $1) if /app\s.*args="([^\/"\s]+).*"/' < "$M3_OUT/boot-all.xml")

    args="--mod boot.xml"
    if [ "$M3_HW_RESET" = "1" ]; then
        args="$args --reset"
    fi
    if [ -n "$M3_HW_TIMEOUT" ]; then
        args="$args --timeout=$M3_HW_TIMEOUT"
    fi
    if [ "$M3_HW_VM" != "0" ]; then
        args="$args --vm"
    fi

    files=("$M3_OUT/boot.xml" "$bindir/tilemux")
    IFS=';'
    c=0
    for karg in $kargs; do
        args="$args --tile '$karg'"
        files=("${files[@]}" "$bindir/${karg%% *}")
        c=$((c + 1))
    done
    for mod in $mods; do
        args="$args --mod '$mod'"
        # use the stripped binary from the default fs
        basemod=$(basename "$mod")
        if [ -f "$build/src/fs/default/bin/$basemod" ]; then
            files=("${files[@]}" "$build/src/fs/default/bin/$basemod")
        else
            files=("${files[@]}" "$build/src/fs/default/sbin/$basemod")
        fi
    done
    while [ $c -lt 8 ]; do
        args="$args --tile tilemux"
        c=$((c + 1))
    done
    unset IFS

    if [ "$(grep '$fs' "$1")" != "" ]; then
        files=("${files[@]}" "$build/$M3_FS")
        args="$args --fs $(basename "$build/$M3_FS")"
    fi

    fpga="--fpga ${M3_HW_FPGA:-0}"

    {
        echo "#!/bin/sh"
        echo "export PYTHONPATH=\$HOME/tcu/fpga_tools/python:\$PYTHONPATH"
        echo "export PYTHONPATH=\$HOME/tcu/fpga_tools/pyelftools-0.26:\$PYTHONPATH"
        # echo "export RUST_FILE_LOG=debug"
        echo ""
        if [ "$debug" != "" ]; then
            # start everything
            echo 'echo -n > .running'
            echo 'trap "rm -f .running 2>/dev/null" SIGINT SIGTERM EXIT'
            echo 'rm -f .ready'
            echo "python3 ./fpga.py $fpga $args --debug $M3_HW_PAUSE &>log.txt &"
            # wait until it's finished or failed
            echo 'fpga=$!'
            echo 'echo "Waiting until FPGA has been initialized..."'
            echo 'while [ "`cat .ready 2>/dev/null`" = "" ] && [ -f /proc/$fpga/cmdline ]; do sleep 1; done'
            # stop if it failed
            echo '[ -f /proc/$fpga/cmdline ] || { cat log.txt && exit 1; }'
            # make sure we clean up everything
            echo 'trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT'
            # start openocd
            echo 'OPENOCD=$HOME/tcu/fpga_tools/debug'
            echo '$OPENOCD/openocd -f $OPENOCD/fpga_switch.cfg >openocd.log 2>&1'

            # make sure that openocd is stopped
            trap "ssh -t $hwssh 'killall openocd'" ERR INT TERM
        else
            echo "python3 ./fpga.py $fpga $args 2>&1 | tee -i log.txt"
        fi
    } > "$M3_OUT/run.sh"

    rsync -z src/tools/fpga.py "${files[@]}" "$M3_OUT/run.sh" "$hwssh:m3"

    ssh -t "$hwssh" "cd m3 && sh run.sh"
    scp "$hwssh:m3/log.txt" "$hwssh:m3/log/pm*" "$M3_OUT"
}

if [ "$M3_TARGET" = "gem5" ] || [ "$M3_RUN_GEM5" = "1" ]; then
    build_params_gem5 "$script"
elif [ "$M3_TARGET" = "hw" ]; then
    build_params_hw "$script"
else
    echo "Unknown target '$M3_TARGET'"
fi

# ensure that we get into cooked mode again
stty sane
