#!/bin/bash

# fall back to reasonable defaults
if [ -z "$M3_BUILD" ]; then
    M3_BUILD='release'
fi
if [ -z "$M3_TARGET" ]; then
    M3_TARGET='host'
fi
if [ -z "$M3_ISA" ]; then
    M3_ISA='x86_64'
fi
if [ -z "$M3_OUT" ]; then
    M3_OUT="run"
fi

# set target
if [ "$M3_TARGET" = "gem5" ]; then
    if [ "$M3_ISA" != "arm" ] && [ "$M3_ISA" != "x86_64" ] && [ "$M3_ISA" != "riscv" ]; then
        echo "ISA $M3_ISA not supported for target gem5." >&2 && exit 1
    fi
elif [ "$M3_TARGET" = "hw" ]; then
    M3_ISA="riscv"
elif [ "$M3_TARGET" = "host" ]; then
    M3_ISA=$(uname -m)
    if [ "$M3_ISA" = "armv7l" ]; then
        M3_ISA="arm"
    fi
else
    echo "Target $M3_TARGET not supported." >&2 && exit 1
fi

export M3_BUILD M3_TARGET M3_ISA M3_OUT

# determine cross compiler and rust ABI based on target and ISA
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$build/bin"
crossprefix=''
if [ "$M3_TARGET" = "gem5" ] || [ "$M3_TARGET" = "hw" ]; then
    crossdir="./build/cross-$M3_ISA/bin"
    if [ "$M3_ISA" = "arm" ]; then
        crossprefix="$crossdir/arm-none-eabi-"
    elif [ "$M3_ISA" = "riscv" ]; then
        crossprefix="$crossdir/riscv64-unknown-elf-"
    else
        crossprefix="$crossdir/x86_64-elf-m3-"
    fi
    export PATH=$crossdir:$PATH
fi
if [ "$M3_TARGET" = "gem5" ] && [ "$M3_ISA" = "arm" ]; then
    rustabi='gnueabihf'
elif [ "$M3_BUILD" = "coverage" ]; then
    rustabi='cov'
else
    rustabi='gnu'
fi

# rust env vars
rusttoolchain=$(readlink -f src/toolchain/rust)
rustbuild=$(readlink -f build/rust)
export RUST_TARGET=$M3_ISA-unknown-$M3_TARGET-$rustabi
export RUST_TARGET_PATH=$rusttoolchain
export CARGO_TARGET_DIR=$rustbuild
export XBUILD_SYSROOT_PATH=$CARGO_TARGET_DIR/sysroot
if [ "$M3_BUILD" = "coverage" ]; then
    if [ "$M3_TARGET" != "host" ]; then
        echo "Coverage mode is only supported with M3_TARGET=host." >&2 && exit 1
    fi
    # we need to disable incremental compilation to use -Zprofile=yes
    export CARGO_INCREMENTAL=0
fi

build=build/$M3_TARGET-$M3_ISA-$M3_BUILD
bindir=$build/bin/

help() {
    echo "Usage: $1 [-n] [<cmd> <arg>]"
    echo ""
    echo "This is a convenience script that is responsible for building everything"
    echo "and running the specified command afterwards. The most important environment"
    echo "variables that influence its behaviour are M3_TARGET=(host|gem5|hw),"
    echo "M3_ISA=(x86_64|arm|riscv) [on gem5 only], and M3_BUILD=(debug|release|coverage)."
    echo ""
    echo "The flag -n skips the build and executes the given command directly. This"
    echo "can be handy if, for example, the build is currently broken."
    echo ""
    echo "The following commands are available:"
    echo "    ninja ...:               run ninja with given arguments."
    echo "    run <script>:            run the specified <script>. See directory boot."
    echo "    rungem5 <script>:        run the specified <script> on gem5. See directory boot."
    echo "    runvalgrind <script>:    run the specified script in valgrind."
    echo "    clippy:                  run clippy for rust code."
    echo "    doc:                     generate rust documentation."
    echo "    fmt:                     run rustfmt for rust code."
    echo "    macros=<path>:           expand rust macros for app in <path>."
    echo "    dbg=<prog> <script>:     run <script> and debug <prog> in gdb"
    echo "    dis=<prog>:              run objdump -SC <prog> (the cross-compiler version)"
    echo "    elf=<prog>:              run readelf -a <prog> (the cc version)"
    echo "    nms=<prog>:              run nm -SC --size-sort <prog> (the cc version)"
    echo "    nma=<prog>:              run nm -SCn <prog> (the cc version)"
    echo "    straddr=<prog> <string>  search for <string> in <prog>"
    echo "    ctors=<prog>:            show the constructors of <prog>"
    echo "    hwitrace=<progs>:        shows an annotated hardware instruction trace. <progs>"
    echo "                             are the binary names for the symbols. stdin expects"
    echo "                             the run/pm*-instrs.log."
    echo "    trace=<progs>:           shows an annotated instruction trace. <progs> are"
    echo "                             the binary names for the symbols. stdin expects the"
    echo "                             gem5.log with Exec,ExecPC enabled."
    echo "    flamegraph=<progs>:      produces a flamegraph with stdin to stdout. <progs>"
    echo "                             are the binary names for the symbols. stdin expects"
    echo "                             the gem5.log with Exec,ExecPC,TcuConnector enabled."
    echo "    snapshot=<progs> <time>: prints the stacktrace of all programs at timestamp"
    echo "                             <time>. <progs> are the binary names for the symbols."
    echo "                             stdin expects the gem5.log with Exec,ExecPC enabled."
    echo "    coverage:                generate code-coverage report. This command is only"
    echo "                             available in coverage mode. It requires to first run"
    echo "                             the system to collect the information. Note that this"
    echo "                             command relies on the grcov tool."
    echo "    mkfs=<fsimg> <dir> ...:  create m3-fs in <fsimg> with content of <dir>"
    echo "    shfs=<fsimg> ...:        show m3-fs in <fsimg>"
    echo "    fsck=<fsimg> ...:        run m3fsck on <fsimg>"
    echo "    exfs=<fsimg> <dir>:      export contents of <fsimg> to <dir>"
    echo "    bt=<prog>:               print the backtrace, using given symbols"
    echo "    list:                    list the link-address of all programs"
    echo ""
    echo "Environment variables:"
    echo "    M3_TARGET:               the target. Either 'host' for using the Linux-based"
    echo "                             coarse-grained simulator, or 'gem5'. The default is"
    echo "                             'host'."
    echo "    M3_ISA:                  the ISA to use. On gem5, 'arm', 'riscv', and 'x86_64'"
    echo "                             is supported. On other targets, it is ignored."
    echo "    M3_BUILD:                the build-type. Either debug, coverage, or release."
    echo "                             In debug mode optimizations are disabled, debug infos"
    echo "                             are available and assertions are active. In coverage"
    echo "                             mode (only available on host), code-coverage info"
    echo "                             is generated. In release mode all that is disabled."
    echo "                             The default is release."
    echo "    M3_KERNEL:               the kernel to use (kernel or rustkernel)."
    echo "    M3_VERBOSE:              print executed commands in detail during build."
    echo "    M3_VALGRIND:             for runvalgrind: pass arguments to valgrind."
    echo "    M3_CORES:                # of cores to simulate."
    echo "    M3_FS:                   The filesystem to use (filename only)."
    echo "    M3_HDD:                  The hard drive image to use (filename only)."
    echo "    M3_OUT:                  The output directory ('run' by default)."
    echo "    M3_GEM5_DBG:             The trace-flags for gem5 (--debug-flags)."
    echo "    M3_GEM5_DBGSTART:        When to start tracing for gem5 (--debug-start)."
    echo "    M3_GEM5_CPU:             The CPU model (detailed by default)."
    echo "    M3_GEM5_TCUPOS:          The TCU position (0=before L1, 1=behind L1 or"
    echo "                             2=behind L2)."
    echo "    M3_GEM5_CPUFREQ:         The CPU frequency (1GHz by default)."
    echo "    M3_GEM5_MEMFREQ:         The memory frequency (333MHz by default)."
    echo "    M3_GEM5_FSNUM:           The number of times to load the FS image."
    echo "    M3_GEM5_PAUSE:           Pause the tile with given number until GDB connects"
    echo "                             (only on gem5 and with command dbg=)."
    echo "    M3_HW_SSH:               The SSH alias for the FPGA PC (default: syn)"
    echo "    M3_HW_FPGA:              The FPGA number (default 0 = IP 192.168.42.240)"
    echo "    M3_HW_RESET:             Reset the FPGA before starting"
    echo "    M3_HW_VM:                Use virtual memory (default = 1)"
    echo "    M3_HW_TIMEOUT:           Stop execution after given number of seconds."
    echo "    M3_HW_PAUSE:             Pause the tile with given number at startup"
    echo "                             (only on hw and with command dbg=)."
    exit 0
}

# parse arguments
case "$1" in
    -h|-\?|--help)
        help "$0"
        ;;
esac

skipbuild=0
cmd=""
script=""
while [ $# -gt 0 ]; do
    if [ "$1" = "-n" ]; then
        skipbuild=1
    elif [ "$cmd" = "" ]; then
        cmd="$1"
    elif [ "$script" = "" ]; then
        script="$1"
    else
        break
    fi
    shift
done

mkdir -p $build $M3_OUT

ninjaargs=()
if [ "$M3_VERBOSE" != "" ]; then
    ninjaargs=("${ninjaargs[@]}" -v)
fi

if [ $skipbuild -eq 0 ]; then
    filesid=$build/.all-files.id
    find src -type f > $filesid.new
    # redo the configuration if any file was added/removed
    if [ ! -f $build/build.ninja ] || ! cmp $filesid.new $filesid &>/dev/null; then
        echo "Configuring for $M3_TARGET-$M3_ISA-$M3_BUILD..." >&2
        ./configure.py || exit 1
        mv $filesid.new $filesid
    fi
fi

# TODO: this is necessary because cargo needs to know
# a cross-compile-gcc for riscv on linux
# (see linux-deps/src/lxclient/.cargo/config for example)
if [ -d build/gem5-riscv-release/linux-deps/buildroot/host/bin ]; then
	export PATH="$(pwd)/build/gem5-riscv-release/linux-deps/buildroot/host/bin:$PATH"
fi

case "$cmd" in
    ninja)
        ninja -f $build/build.ninja "${ninjaargs[@]}" "$script" "$@"
        exit $?
        ;;
esac

if [ $skipbuild -eq 0 ]; then
    echo "Building for $M3_TARGET-$M3_ISA-$M3_BUILD..." >&2
    ninja -f $build/build.ninja "${ninjaargs[@]}" >&2 || {
        # ensure that we regenerate the build.ninja next time. Since ninja does not accept the
        # build.ninja, it will also not detect changes our build files in order to regenerate it.
        # Therefore, force ourself to regenerate it by removing our "files id".
        rm -f $filesid
        exit 1
    }
fi

run_on_host() {
    echo -n > $M3_OUT/log.txt
    tail -f $M3_OUT/log.txt &
    tailpid=$!
    trap 'stty sane && kill $tailpid' INT
    ./src/tools/execute.sh "$1"
    kill $tailpid
}

childpids() {
    n=0
    for pid in $(ps h -o pid --ppid "$1"); do
        if [ $n -gt 0 ]; then
            echo -n ","
        fi
        echo -n "$pid"
        list=$(childpids "$pid")
        if [ "$list" != "" ]; then
            echo -n ",$list"
        fi
        n=$((n + 1))
    done
}

findprog() {
    pids=$(childpids "$1")
    if [ "$pids" != "" ]; then
        # shellcheck disable=SC2009
        ps hww -o pid,cmd -p "$pids" | grep "^\s*[[:digit:]]* [^ ]*$2\b"
    fi
}

# run the specified command, if any
case "$cmd" in
    run)
        if [ "$M3_TARGET" = "host" ]; then
            run_on_host "$script"
        else
            if [ "$DBG_GEM5" = "1" ]; then
                ./src/tools/execute.sh "$script"
            else
                ./src/tools/execute.sh "$script" 2>&1 | tee $M3_OUT/log.txt
            fi
        fi
        ;;

    rungem5)
        if [ "$M3_TARGET" = "gem5" ] || [ "$M3_TARGET" = "hw" ]; then
            M3_RUN_GEM5=1 ./src/tools/execute.sh "$script" 2>&1 | tee $M3_OUT/log.txt
        else
            echo "Not supported"
        fi
        ;;

    runvalgrind)
        if [ "$M3_TARGET" = "host" ]; then
            export M3_VALGRIND=${M3_VALGRIND:-"--leak-check=full"}
            run_on_host "$script"
        else
            echo "Not supported"
        fi
        ;;

    clippy)
        while IFS= read -r -d '' f; do
            # some crates can't be built for host
            if [ "$M3_TARGET" = "host" ] &&
                ( [[ $f =~ "tilemux" ]] || [[ $f =~ "paging" ]] || [[ $f =~ "isr" ]] ||
                  [[ $f =~ "stdareceiver" ]] || [[ $f =~ "stdasender" ]] ); then
                continue;
            fi
            # vmtest only works on RISC-V
            if [ "$M3_ISA" != "riscv" ] && [[ $f =~ "vmtest" ]]; then
                continue;
            fi
            # gem5log+hwitrace are always built for the host OS (not our host target)
            target=()
            if [[ ! $f =~ "gem5log" ]] && [[ ! $f =~ "hwitrace" ]] && [[ ! $f =~ "netdbg" ]]; then
                target=("${target[@]}" -Z "build-std=core,alloc" --target "$RUST_TARGET")
            fi
            echo "Running clippy for $(dirname "$f")..."
            ( cd "$(dirname "$f")" && cargo clippy "${target[@]}" -- \
                -A clippy::identity_op \
                -A clippy::manual_range_contains \
                -A clippy::assertions_on_constants \
                -A clippy::upper_case_acronyms \
                -A clippy::empty_loop )
        done < <(find src -mindepth 2 -name Cargo.toml -print0)
        ;;

    doc)
        export RUSTFLAGS="--sysroot $XBUILD_SYSROOT_PATH"
        export RUSTDOCFLAGS=$RUSTFLAGS
        for lib in src/libs/rust/*; do
            if [ -d "$lib" ]; then
                # some crates can't be built for host
                if [ "$M3_TARGET" = "host" ] && [[ $lib =~ "isr" ]]; then
                    continue;
                fi
                ( cd "$lib" && cargo doc -Z build-std=core,alloc --target $RUST_TARGET )
            fi
        done
        ;;

    fmt)
        while IFS= read -r -d '' f; do
            if [[ "$f" =~ "src/libs/musl" ]] && [[ ! "$f" =~ "src/libs/musl/m3" ]]; then
                continue
            fi
            if [[ "$f" =~ "src/libs/flac" ]] || [[ "$f" =~ "src/apps/bsdutils" ]] ||
                [[ "$f" =~ "src/libs/leveldb" ]] || [[ "$f" =~ "src/libs/llvmprofile" ]] ||
                [[ "$f" =~ "src/libs/axieth" ]]; then
                continue
            fi

            echo "Formatting $f..."
            clang-format -i "$f"
        done < <(find src \( -name "*.cc" -or -name "*.h" \) -print0)

        while IFS= read -r -d '' f; do
            echo "Formatting $(dirname "$f")..."
            rustfmt "$(dirname "$f")"/src/*.rs
        done < <(find src -mindepth 2 -name Cargo.toml -print0)
        ;;

    macros=*)
        export RUSTFLAGS="--sysroot $XBUILD_SYSROOT_PATH"
        ( cd "${cmd#macros=}" && \
            cargo rustc --target $RUST_TARGET --profile=check \
                -- -Zunstable-options --pretty=expanded | less )
        ;;

    dbg=*)
        if [ "$M3_TARGET" = "host" ]; then
            # does not work in release mode
            if [ "$M3_BUILD" = "release" ]; then
                echo "Only supported with M3_BUILD=debug or M3_BUILD=coverage."
                exit 1
            fi

            # ensure that we can ptrace non-child-processes
            if [ "$(cat /proc/sys/kernel/yama/ptrace_scope)" = "1" ]; then
                echo "We need to enable ptrace for non-child processes via sudo first:"
                echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope || exit 1
            fi

            prog="${cmd#dbg=}"
            M3_WAIT="$prog" ./src/tools/execute.sh "$script" "--debug=${cmd#dbg=}" &
            shpid=$!
            M3_KERNEL=${M3_KERNEL:-kernel}

            pid=$(pgrep -x "$M3_KERNEL")
            while [ "$pid" = "" ]; do
                sleep 1
                pid=$(pgrep -x "$M3_KERNEL")
            done
            if [ "$prog" != "$M3_KERNEL" ]; then
                line=$(findprog "$pid" "$prog")
                while [ "$line" = "" ]; do
                    sleep 1
                    line=$(findprog "$pid" "$prog")
                done
                pid=$(findprog "$pid" "$prog" | xargs | cut -d ' ' -f 1)
            fi

            tmp=$(mktemp)
            {
                echo "display/i \$pc"
                echo "b main"
                echo "set var wait_for_debugger = 0"
            } > "$tmp"
            rust-gdb --tui "$build/bin/$prog" "$pid" --command="$tmp"

            kill $shpid
            rm "$tmp"
        elif [ "$M3_TARGET" = "gem5" ] || [ "$M3_RUN_GEM5" = "1" ]; then
            truncate --size 0 $M3_OUT/log.txt
            ./src/tools/execute.sh "$script" "--debug=${cmd#dbg=}" 1>$M3_OUT/log.txt 2>&1 &

            # wait until it has started
            while [ "$(grep --text "Global frequency set at" $M3_OUT/log.txt)" = "" ]; do
                sleep 1
            done

            if [ "$M3_GEM5_PAUSE" != "" ]; then
                port=$((M3_GEM5_PAUSE + 7000))
            else
                echo "Warning: M3_GEM5_PAUSE not specified; gem5 won't wait for GDB."
                tile=$(grep --text "^T.*$build/bin/${cmd#dbg=}" $M3_OUT/log.txt | cut -d : -f 1)
                port=$((${tile#T} + 7000))
            fi

            gdbcmd=$(mktemp)
            {
                echo "target remote localhost:$port"
                echo "display/i \$pc"
                echo "b main"
            } > "$gdbcmd"
            RUST_GDB=${crossprefix}gdb rust-gdb --tui "$bindir/${cmd#dbg=}" "--command=$gdbcmd"

            killall -9 gem5.opt
            rm "$gdbcmd"
        else
            if [ "$M3_HW_PAUSE" = "" ]; then
                echo "Please set M3_HW_PAUSE to the tile to debug."
                exit 1
            fi
            ./src/tools/execute.sh "$script" "--debug=${cmd#dbg=}" &>/dev/null &

            port=$((3340 + M3_HW_PAUSE))
            ssh -N -L 30000:localhost:$port "${M3_HW_SSH:-syn}" 2>/dev/null &
            trap 'trap - SIGTERM && kill -- -$$' SIGINT SIGTERM EXIT

            echo -n "Connecting..."
            time=0
            while [ "$(telnet localhost 30000 2>/dev/null | grep '\+')" = "" ]; do
                # after some warmup, detect if something went wrong
                if [ $time -gt 5 ]; then
                    ssh "${M3_HW_SSH:-syn}" "test -e m3/.running" ||
                        { echo "Remote side stopped." && exit 1; }
                fi
                echo -n "."
                sleep 1
                time=$((time + 1))
            done

            gdbcmd=$(mktemp)
            {
                echo "target remote localhost:30000"
                echo "set \$t0 = 0"                  # ensure that we set the default stack pointer
                echo "set \$pc = 0x10000000"         # go to entry point
            } > "$gdbcmd"

            # differentiate between baremetal components and others
            entry=$(${crossprefix}readelf -h "$bindir/${cmd#dbg=}" | \
                grep "Entry point" | awk '{ print($4) }')
            if [ "$entry" = "0x10000000" ]; then
                echo "b env_run" >> "$gdbcmd"
                symbols=$bindir/${cmd#dbg=}
            else
                {
                    echo "tb __app_start"
                    echo "c"
                    echo "symbol-file $bindir/${cmd#dbg=}"
                    echo "b main"
                } >> "$gdbcmd"
                symbols=$bindir/tilemux
            fi
            echo "display/i \$pc" >> "$gdbcmd"

            RUST_GDB=${crossprefix}gdb rust-gdb --tui "$symbols" "--command=$gdbcmd"
        fi
        ;;

    coverage)
        if [ "$M3_BUILD" != "coverage" ]; then
            echo "Only support for M3_BUILD=coverage." >&2 && exit 1
        fi
        echo "Generating code-coverage report..."
        grcov . -s . --binary-path build -t html --ignore="platform/*" --ignore-not-existing -o $build/coverage
        echo "You find the results in $(readlink -f $build/coverage/index.html)"
        ;;

    dis=*)
        ${crossprefix}objdump -dC "$bindir/${cmd#dis=}" | less
        ;;

    elf=*)
        ${crossprefix}readelf -aW "$bindir/${cmd#elf=}" | c++filt | less
        ;;

    nms=*)
        ${crossprefix}nm -SC --size-sort "$bindir/${cmd#nms=}" | less
        ;;

    nma=*)
        ${crossprefix}nm -SCn "$bindir/${cmd#nma=}" | less
        ;;

    straddr=*)
        binary=$bindir/${cmd#straddr=}
        str=$script
        echo "Strings containing '$str' in $binary:"
        # find base address of .rodata
        base=$(${crossprefix}readelf -S "$binary" | grep .rodata | \
            xargs | cut -d ' ' -f 5)
        # find section number of .rodata
        section=$(${crossprefix}readelf -S "$binary" | grep .rodata | \
            sed -e 's/.*\[\s*\([[:digit:]]*\)\].*/\1/g')
        # grep for matching lines, prepare for better use of awk and finally add offset to base
        ${crossprefix}readelf -p "$section" "$binary" | grep "$str" | \
            sed 's/^ *\[ *\([[:xdigit:]]*\)\] *\(.*\)$/0x\1 \2/' | \
            awk '{ printf("0x%x: %s %s %s %s %s %s\n",0x'"$base"' + strtonum($1),$2,$3,$4,$5,$6,$7) }'
        ;;

    ctors=*)
        file=$bindir/${cmd#ctors=}
        section=$(${crossprefix}readelf -SW "$file" | \
            grep "\.ctors\|\.init_array" | sed -e 's/\[.*\]//g' | xargs)
        off=0x$(echo "$section" | cut -d ' ' -f 4)
        len=0x$(echo "$section" | cut -d ' ' -f 5)
        if [ "$M3_ISA" = "x86_64" ] || [ "$M3_ISA" = "riscv" ]; then
            bytes=8
        else
            bytes=4
        fi
        echo "Constructors in $file ($off : $len):"
        if [ "$off" != "0x" ]; then
            od -t x$bytes "$file" -j "$off" -N "$len" -v -w$bytes | grep ' ' | while read -r line; do
                addr=${line#* }
                ${crossprefix}nm -C -l "$file" 2>/dev/null | grep -m 1 "$addr"
            done
        fi
        ;;

    hwitrace=*)
        paths=()
        names=${cmd#hwitrace=}
        for f in ${names//,/ }; do
            paths=("${paths[@]}" "$build/bin/$f")
        done
        $build/tools/hwitrace $crossprefix "${paths[@]}" | less
        ;;

    trace=*)
        paths=()
        names=${cmd#trace=}
        for f in ${names//,/ }; do
            paths=("${paths[@]}" "$build/bin/$f")
        done
        $build/tools/gem5log $M3_ISA trace "${paths[@]}" | less
        ;;

    flamegraph=*)
        paths=()
        names=${cmd#flamegraph=}
        for f in ${names//,/ }; do
            paths=("${paths[@]}" "$build/bin/$f")
        done
        # inferno-flamegraph is available at https://github.com/jonhoo/inferno
        $build/tools/gem5log $M3_ISA flamegraph "${paths[@]}" | inferno-flamegraph --countname ns
        ;;

    snapshot=*)
        paths=()
        names=${cmd#snapshot=}
        for f in ${names//,/ }; do
            paths=("${paths[@]}" "$build/bin/$f")
        done
        $build/tools/gem5log $M3_ISA snapshot "$script" "${paths[@]}"
        ;;

    mkfs=*)
        $build/tools/mkm3fs "$build/${cmd#mkfs=}" "$script" "$@"
        ;;

    shfs=*)
        $build/tools/shm3fs "$build/${cmd#shfs=}" "$script" "$@"
        ;;

    fsck=*)
        $build/tools/m3fsck "$build/${cmd#fsck=}" "$script"
        ;;

    exfs=*)
        $build/tools/exm3fs "$build/${cmd#exfs=}" "$script"
        ;;

    bt=*)
        ./src/tools/backtrace.py "$crossprefix" "$bindir/${cmd#bt=}"
        ;;

    list)
        echo "Start of section .text:"
        while IFS= read -r -d '' l; do
            ${crossprefix}readelf -S "$build/bin/$l" | \
                grep " \.text " | awk "{ printf(\"%20s: %s\n\",\"$l\",\$5) }"
        done < <(find $build/bin -type f \! \( -name "*.o" -o -name "*.a" \) -printf "%f\0") | sort -k 2
        ;;
esac
