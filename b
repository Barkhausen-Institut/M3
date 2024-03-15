#!/usr/bin/env bash

# fall back to reasonable defaults
if [ -z "$M3_BUILD" ]; then
    M3_BUILD='release'
fi
if [ -z "$M3_TARGET" ]; then
    M3_TARGET='gem5'
fi
if [ -z "$M3_ISA" ]; then
    M3_ISA='riscv64'
fi
if [ -z "$M3_OUT" ]; then
    M3_OUT="run"
fi

# set target
if [ "$M3_TARGET" = "gem5" ]; then
    if [ "$M3_ISA" != "arm" ] && [ "$M3_ISA" != "x86_64" ] && [ "$M3_ISA" != "riscv64" ]; then
        echo "ISA $M3_ISA not supported for target gem5." >&2 && exit 1
    fi
elif [ "$M3_TARGET" = "hw" ] || [ "$M3_TARGET" = "hw22" ] || [ "$M3_TARGET" = "hw23" ]; then
    M3_ISA="riscv64"
else
    echo "Target $M3_TARGET not supported." >&2 && exit 1
fi

if [ "$M3_BUILD" != "debug" ] && [ "$M3_BUILD" != "release" ] &&
    [ "$M3_BUILD" != "bench" ] && [ "$M3_BUILD" != "coverage" ]; then
    echo "Build mode $M3_BUILD not supported." >&2 && exit 1
fi
if [ "$M3_BUILD" = "coverage" ] && [ "$M3_ISA" != "riscv64" ] && [ "$M3_ISA" != "x86_64" ]; then
    echo "Coverage mode is only supported with M3_ISA=riscv64 and M3_ISA=x86_64." >&2 && exit 1
fi

export M3_BUILD M3_TARGET M3_ISA M3_OUT

# determine cross compiler and rust ABI based on target and ISA
root=$(readlink -f .)
crossdir="./build/cross-$M3_ISA/host"
if [ "$M3_ISA" = "arm" ]; then
    crossname="arm-buildroot-linux-musleabi-"
elif [ "$M3_ISA" = "riscv64" ]; then
    crossname="riscv64-buildroot-linux-musl-"
else
    crossname="x86_64-buildroot-linux-musl-"
fi
crossprefix="$crossdir/bin/$crossname"
PATH="$root/$crossdir/bin:$PATH"
export PATH
if [ "$M3_TARGET" = "gem5" ] && [ "$M3_ISA" = "arm" ]; then
    rustabi='musleabi'
elif [ "$M3_BUILD" = "coverage" ]; then
    rustabi='muslcov'
else
    rustabi='musl'
fi

build=build/$M3_TARGET-$M3_ISA-$M3_BUILD
bindir=$build/bin/
tooldir=$build/toolsbin

# rust env vars
rusttoolchain="$root/src/toolchain/rust"
rustbuild="$root/$build/rust"
rustisa="$M3_ISA"
export RUST_TARGET=$rustisa-linux-m3-$rustabi
export RUST_TARGET_PATH=$rusttoolchain
rust_host_args=(--target-dir "$rustbuild")
rust_target_args=(
    --target "$RUST_TARGET" --target-dir "$rustbuild"
    -Z "build-std=core,alloc,std,panic_abort"
)

# configure TARGET_CFLAGS for llvmprofile within minicov (only used with RISC-V)
if [[ "$M3_ISA" = "riscv64" && "$M3_BUILD" = "coverage" ]]; then
    flags="-march=rv64imafdc -mabi=lp64d"
    # add C include paths to ensure that these instead of the include paths for the clang host
    # compiler will be used
    paths=(
        "src/include"
        "src/libs/musl/arch/$rustisa"
        "src/libs/musl/arch/generic"
        "src/libs/musl/m3/include/$M3_ISA"
        "src/libs/musl/include"
    )
    for p in "${paths[@]}"; do
        flags="$flags -I$(readlink -f "$p")"
    done
    export TARGET_CFLAGS="$flags"
fi

help() {
    echo "Usage: $1 [-n] [<cmd> <arg>]"
    echo ""
    echo "This is a convenience script that is responsible for building everything"
    echo "and running the specified command afterwards. The most important environment"
    echo "variables that influence its behaviour are M3_TARGET=(gem5|hw|hw22|hw23),"
    echo "M3_ISA=(x86_64|arm|riscv64) [on gem5 only], and"
    echo "M3_BUILD=(debug|release|bench|coverage)."
    echo ""
    echo "The flag -n skips the build and executes the given command directly. This"
    echo "can be handy if, for example, the build is currently broken."
    echo ""
    echo "The following commands are available:"
    echo "  Building:"
    echo "    clean:                   remove build directory for the current M3_TARGET,"
    echo "                             M3_ISA, and M3_BUILD combination. This requires a"
    echo "                             complete rebuild afterwards."
    echo "    distclean:               removes the entire build directory, requiring also"
    echo "                             a rebuild of the cross compiler. Use with caution!"
    echo "    ninja ...:               run ninja with given arguments."
    echo ""
    echo "  Running:"
    echo "    run <script>:            run the specified <script>. See directory boot."
    echo "    rungem5 <script>:        run the specified <script> on gem5. See directory boot."
    echo "    loadfpga=<bitfile>:      loads the given Bitfile onto the FPGA. The Bitfile is"
    echo "                             specified relative to platform/hw/fpga_tools/bitfiles."
    echo ""
    echo "  Debugging:"
    echo "    dbg=<prog> <script>:     run <script> and debug <prog> in gdb."
    echo "    bt=<prog>:               print the backtrace, using given symbols."
    echo "    hwitrace=<progs>:        shows an annotated hardware instruction trace. <progs>"
    echo "                             are the binary names for the symbols. stdin expects"
    echo "                             the run/pm*-instrs.log."
    echo "    trace=<progs>:           shows an annotated instruction trace. <progs> are"
    echo "                             the binary names for the symbols, separated by ','."
    echo "                             Optionally, each binary can end with '+<offset>' in"
    echo "                             case of ASLR. stdin expects the gem5.log with Exec"
    echo "                             enabled."
    echo "    flamegraph=<progs>:      produces a flamegraph with stdin to stdout. <progs>"
    echo "                             are the binary names for the symbols. stdin expects"
    echo "                             the gem5.log with Exec,TcuConnector enabled."
    echo "    snapshot=<progs> <time>: prints the stacktrace of all programs at timestamp"
    echo "                             <time>. <progs> are the binary names for the symbols."
    echo "                             stdin expects the gem5.log with Exec enabled."
    echo ""
    echo "  Program analysis:"
    echo "    ctors=<prog>:            show the constructors of <prog>."
    echo "    dis=<prog>:              run objdump -SC <prog>."
    echo "    elf=<prog>:              run readelf -a <prog>."
    echo "    list:                    list the link-address of all programs."
    echo "    macros=<path>:           expand Rust macros for app in <path>."
    echo "    nma=<prog>:              run nm -SCn <prog>."
    echo "    nms=<prog>:              run nm -SC --size-sort <prog>."
    echo "    straddr=<prog> <string>  search for <string> in <prog>."
    echo ""
    echo "  File system:"
    echo "    exfs=<fsimg> <dir>:      export contents of <fsimg> to <dir>."
    echo "    fsck=<fsimg> ...:        run m3fsck on <fsimg>."
    echo "    mkfs=<fsimg> <dir> ...:  create m3fs in <fsimg> with content of <dir>."
    echo "    shfs=<fsimg> ...:        show m3fs in <fsimg>."
    echo ""
    echo "  Maintenance:"
    echo "    checkboot:               check the validity of all boot scripts."
    echo "    clippy:                  run clippy for all Rust code."
    echo "    clippy=<prog>:           run clippy for Rust code in given directory."
    echo "    doc:                     generate Rust documentation."
    echo "    fmt:                     run formatters for all C++, Rust, and Python code."
    echo ""
    echo "  M³Linux (RISC-V only):"
    echo "    mklx ...:                (re)build Linux including bbl via buildroot. The"
    echo "                             remaining arguments are passed to Linux's build system."
    echo "    mkbbl ...:               (re)build the bbl bootloader. The remaining arguments"
    echo "                             are passed to bbl's build system."
    echo "    genlxcc:                 Generate compile_commands.json for M³Linux."
    echo ""
    echo "Environment variables:"
    echo "  General:"
    echo "    M3_TARGET:               the target: 'gem5', 'hw', 'hw22', or 'hw23', default"
    echo "                             is 'gem5'."
    echo "    M3_ISA:                  the ISA to use. On gem5, 'arm', 'riscv64', and 'x86_64'"
    echo "                             is supported. On other targets, it is ignored."
    echo "    M3_BUILD:                the build type is 'debug', 'release', 'bench' or"
    echo "                             'coverage'. In debug mode optimizations are disabled,"
    echo "                             debug infos are available, and assertions are active."
    echo "                             In release mode all that is disabled. In bench, all"
    echo "                             logging is hardcoded to Info,Error in contrast to all"
    echo "                             other modes where it is defined by the environment"
    echo "                             variable LOG (see M3_LOG). The coverage is mode is only"
    echo "                             used for code coverage. The default mode is release."
    echo "    M3_REM_HOST:             if set, the build is performed on this host in"
    echo "                             M3_REM_DIR. All source files are synced to the remote"
    echo "                             host before the build and the build files are synced"
    echo "                             back afterwards."
    echo "    M3_REM_DIR:              the directory in which the remote build takes place."
    echo "    M3_VERBOSE:              print executed commands in detail during build."
    echo "    M3_MOD_PATH:             The path for additional boot modules (build directory"
    echo "                             by default)."
    echo "    M3_OUT:                  the output directory ('run' by default)."
    echo "    M3_LOG:                  the log flags for M³ separated by comma (the log flags"
    echo "                             are listed in src/libs/rust/base/src/io/loglvl.rs). By"
    echo "                             default, M3_LOG is set to 'Info,Error'."
    echo ""
    echo "  Variables for target gem5:"
    echo "    M3_GEM5_CORES:           number of cores to simulate."
    echo "    M3_GEM5_HDD:             the hard drive image to use (filename only)."
    echo "    M3_GEM5_LOG:             the log flags for gem5 (--debug-flags)."
    echo "    M3_GEM5_LOGSTART:        when to start logging for gem5 (--debug-start)."
    echo "    M3_GEM5_CFG:             the gem5 configuration (config/default.py by default)."
    echo "    M3_GEM5_CPU:             the CPU model (DerivO3CPU by default)."
    echo "    M3_GEM5_CPUFREQ:         the CPU frequency (1GHz by default)."
    echo "    M3_GEM5_MEMFREQ:         the memory frequency (333MHz by default)."
    echo "    M3_GEM5_PAUSE:           pause the tile with given id until GDB connects"
    echo "                             (only with command dbg=). Numbers are translated into"
    echo "                             C0T<number>, but ids can also be specified in the form"
    echo "                             of 'C<chip>T<tile>'."
    echo ""
    echo "  Variables for target hw/hw22/hw23:"
    echo "    M3_HW_FPGA_HOST:         the SSH alias for the FPGA PC."
    echo "    M3_HW_FPGA_DIR:          the directory on the FPGA PC to use for temporary"
    echo "                             files. The directory will be created automatically."
    echo "    M3_HW_FPGA_NO:           the FPGA number. Every FPGA has an IP of"
    echo "                             192.168.42.240 + \$M3_HW_FPGA_NO."
    echo "    M3_HW_FPGA_JTAG_NO:      the number of the FPGA JTAG cable. Only relevant if"
    echo "                             there are multiple FPGAs attached to the same PC"
    echo "                             (default = 0)."
    echo "    M3_HW_VIVADO:            absolute path on FPGA PC to Vivado/Vivado Lab."
    echo "    M3_HW_TTY:               TTY device to use for the serial console (for M³Lx)."
    echo "    M3_HW_RESET:             reset the FPGA before starting."
    echo "    M3_HW_VM:                use virtual memory (default = 1)."
    echo "    M3_HW_TIMEOUT:           stop execution after given number of seconds."
    echo "    M3_HW_PAUSE:             pause the tile with given number at startup"
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

mkdir -p "$build" "$M3_OUT"
export NPBUILD="$build"

ninjaargs=()
ninjapieargs=()
if [ "$M3_VERBOSE" = "1" ]; then
    ninjaargs=("${ninjaargs[@]}" -v)
fi
# force regeneration of the ninja build file if the verbosity level changed since last run
if [ "$(cat "$build/.verbose" 2>/dev/null)" != "M3_VERBOSE=$M3_VERBOSE" ]; then
    ninjapieargs=(build -f)
fi
echo "M3_VERBOSE=$M3_VERBOSE" > "$build/.verbose"

case "$cmd" in
    clean)
        rm -rf "$build"
        rm -rf "${rustbuild:?}/debug" "${rustbuild:?}/release"
        exit
        ;;

    distclean)
        rm -rf build
        exit
        ;;

    ninja)
        python3 -B ./tools/ninjapie/ninjapie "${ninjapieargs[@]}" -- "${ninjaargs[@]}" "$script" "$@"
        exit $?
        ;;

    # these commands require on hw that the M3_HW_FPGA_* vars are defined
    run|dbg=*|loadfpga=*)
        if [ "$M3_TARGET" = "hw" ] || [ "$M3_TARGET" = "hw22" ] || [ "$M3_TARGET" = "hw23" ]; then
            if [ -z "$M3_HW_FPGA_HOST" ] || [ -z "$M3_HW_FPGA_DIR" ]; then
                echo "Please define M3_HW_FPGA_HOST and M3_HW_FPGA_DIR." >&2 && exit 1
            fi
            if [ -z "$M3_HW_FPGA_NO" ]; then
                echo "Please define M3_HW_FPGA_NO." >&2 && exit 1
            fi
        fi
        ;;
esac

if [ $skipbuild -eq 0 ]; then
    if [ "$M3_REM_HOST" != "" ]; then
        echo "Building for $M3_TARGET-$M3_ISA-$M3_BUILD remotely at $M3_REM_HOST:$M3_REM_DIR..." >&2
        # sync all sources to the remote host and check whether anything was transferred
        if [ "$(rsync -az --delete . --stats \
                    "--exclude=/.ninja*" --exclude=/platform --exclude=/build --exclude=/cross \
                    --exclude=/run --exclude=/.git \
                    "$M3_REM_HOST:$M3_REM_DIR" |
                grep "Number of regular files transferred: 0")" = "" ] ||
           # if we switched the build directory, rebuild in any case
           [ "$(cat .remote-build 2>/dev/null)" != "$M3_TARGET-$M3_ISA-$M3_BUILD" ]; then
            # remember the last build directory
            echo -n "$M3_TARGET-$M3_ISA-$M3_BUILD" > .remote-build
            # build it on the remote host. source the .profile to set environment variables (e.g.
            # PATH to include ~/.cargo/bin).
            if ssh "$M3_REM_HOST" \
                   'source .profile && ' \
                   'cd '"$M3_REM_DIR"' && ' \
                   'M3_VERBOSE='"$M3_VERBOSE"' ' \
                   'M3_BUILD='"$M3_BUILD"' M3_TARGET='"$M3_TARGET"' M3_ISA='"$M3_ISA"' ./b'; then
                # and transfer build files back
                rsync -az \
                    "$M3_REM_HOST:$M3_REM_DIR/build/$M3_TARGET-$M3_ISA-$M3_BUILD/" \
                    "build/$M3_TARGET-$M3_ISA-$M3_BUILD/"
            else
                # store the current date to some file to ensure that we transfer something next time
                # we try to build, regardless of whether something changed.
                date --rfc-3339=ns > .remote-build-failed
                exit 1
            fi
        fi
    else
        echo "Building for $M3_TARGET-$M3_ISA-$M3_BUILD..." >&2
        python3 -B ./tools/ninjapie/ninjapie "${ninjapieargs[@]}" -- "${ninjaargs[@]}" || exit 1
    fi
fi

run_clippy() {
    target=()
    if [[ "$1" = tools/* ]]; then
        target=("${rust_host_args[@]}")
    elif [[ "$1" = src/m3lx/* ]]; then
        target=(--target riscv64gc-unknown-linux-gnu
                --target-dir "$rustbuild"
                -Z "build-std=core,alloc,std,panic_abort")
    else
        target=("${rust_target_args[@]}")
    fi
    echo "Running clippy for $(dirname "$1")..."
    ( cd "$(dirname "$1")" && cargo clippy "${target[@]}" -- \
        -A clippy::identity_op \
        -A clippy::manual_range_contains \
        -A clippy::assertions_on_constants \
        -A clippy::upper_case_acronyms \
        -A clippy::empty_loop )
}

# run the specified command, if any
case "$cmd" in
    # -- running --

    run)
        if [ "$DBG_GEM5" = "1" ]; then
            ./tools/execute.sh "$crossname" "$script"
        else
            ./tools/execute.sh "$crossname" "$script" 2>&1 | tee "$M3_OUT/log.txt"
        fi
        ;;

    rungem5)
        M3_RUN_GEM5=1 ./tools/execute.sh "$crossname" "$script" 2>&1 | tee "$M3_OUT/log.txt"
        ;;

    loadfpga=*)
        if [ "$M3_TARGET" != "hw" ] && [ "$M3_TARGET" != "hw22" ] && [ "$M3_TARGET" != "hw23" ]; then
            echo "Only supported on M3_TARGET={hw,hw22,hw23}." >&2 && exit 1
        fi
        if [ -z "$M3_HW_VIVADO" ]; then
            echo "Please define M3_HW_VIVADO to the absolute path to Vivado." >&2 && exit 1
        fi
        if [ -z "$M3_HW_FPGA_JTAG_NO" ]; then
            M3_HW_FPGA_JTAG_NO=0
        fi

        bitfile=${cmd#loadfpga=}
        fpgatools="platform/hw/fpga_tools"
        if [ ! -f "$fpgatools/bitfiles/$bitfile" ]; then
            echo "Bitfile '$fpgatools/bitfiles/$bitfile' does not exist." >&2 && exit 1
        fi

        rsync -z \
            "$fpgatools/bitfiles/$bitfile" \
            "$fpgatools/scripts/program_fpga.tcl" \
            "$M3_HW_FPGA_HOST:$M3_HW_FPGA_DIR"

        ssh "$M3_HW_FPGA_HOST" \
            "$M3_HW_VIVADO"' -mode batch \
                             -source '"$M3_HW_FPGA_DIR"'/program_fpga.tcl \
                             -tclargs '"$M3_HW_FPGA_DIR"'/'"$bitfile" "$M3_HW_FPGA_JTAG_NO"
        ;;

    # -- debugging --

    dbg=*)
        if [ "$M3_TARGET" = "gem5" ] || [ "$M3_RUN_GEM5" = "1" ]; then
            if [ "$M3_GEM5_PAUSE" = "" ]; then
                echo "Please set M3_GEM5_PAUSE to the tile to debug (e.g., '1' or 'C1T04')."
                exit 1
            fi

            truncate --size 0 "$M3_OUT/log.txt"
            ./tools/execute.sh "$crossname" "$script" "--debug=${cmd#dbg=}" 1>"$M3_OUT/log.txt" 2>&1 &

            # wait until we know the port
            port=""
            attemps=0
            while [ "$port" = "" ]; do
                if [[ $M3_GEM5_PAUSE =~ C.*T.* ]]; then
                    tile="$M3_GEM5_PAUSE"
                else
                    tile=$(printf "C0T%02d" "$M3_GEM5_PAUSE")
                fi
                port=$(grep --text "$tile.remote_gdb" "$M3_OUT/log.txt" | cut -d ' ' -f 7)
                if [ "$port" = "" ]; then
                    if [ $attemps -gt 5 ]; then
                        echo "Unable to find port for tile '$tile' after 5 attempts."
                        exit 1
                    fi
                    sleep 1
                fi
                attemps=$((attemps + 1))
            done

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
            ./tools/execute.sh "$crossname" "$script" "--debug=${cmd#dbg=}" &>/dev/null &

            port=$((3340 + M3_HW_PAUSE))
            ssh -N -L 30000:localhost:$port "$M3_HW_FPGA_HOST" 2>/dev/null &
            trap 'trap - SIGTERM && kill -- -$$' SIGINT SIGTERM EXIT

            echo -n "Connecting..."
            time=0
            while [ "$(telnet localhost 30000 2>/dev/null | grep '\+')" = "" ]; do
                # after some warmup, detect if something went wrong
                if [ $time -gt 5 ]; then
                    ssh "$M3_HW_FPGA_HOST" "test -e m3/.running" ||
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
            entry=$("${crossprefix}readelf" -h "$bindir/${cmd#dbg=}" | \
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

    bt=*)
        ./tools/backtrace.py "$crossprefix" "$bindir/${cmd#bt=}"
        ;;

    hwitrace=*)
        paths=()
        names=${cmd#hwitrace=}
        for f in ${names//,/ }; do
            paths=("${paths[@]}" "$build/bin/$f")
        done
        "$tooldir/hwitrace" "$crossprefix" "${paths[@]}" | less
        ;;

    trace=*)
        paths=()
        names=${cmd#trace=}
        for f in ${names//,/ }; do
            paths=("${paths[@]}" "$build/bin/$f")
        done
        "$tooldir/gem5log" "$M3_ISA" trace "${paths[@]}" | less
        ;;

    tracelx=*)
        paths=("build/linux/vmlinux" "build/riscv-pk/bbl")
        names=${cmd#tracelx=}
        for f in ${names//,/ }; do
            paths=("${paths[@]}" "$build/lxbin/$f+0x2AAAAAA000")
        done
        "$tooldir/gem5log" "$M3_ISA" trace "${paths[@]}" | less
        ;;

    flamegraph=*)
        paths=()
        names=${cmd#flamegraph=}
        for f in ${names//,/ }; do
            paths=("${paths[@]}" "$build/bin/$f")
        done
        # inferno-flamegraph is available at https://github.com/jonhoo/inferno
        "$tooldir/gem5log" "$M3_ISA" flamegraph "${paths[@]}" | inferno-flamegraph --countname ns
        ;;

    snapshot=*)
        paths=()
        names=${cmd#snapshot=}
        for f in ${names//,/ }; do
            paths=("${paths[@]}" "$build/bin/$f")
        done
        "$tooldir/gem5log" "$M3_ISA" snapshot "$script" "${paths[@]}"
        ;;

    # -- program analysis --

    ctors=*)
        file=$bindir/${cmd#ctors=}
        section=$("${crossprefix}readelf" -SW "$file" | \
            grep "\.ctors\|\.init_array" | sed -e 's/\[.*\]//g' | xargs)
        off=0x$(echo "$section" | cut -d ' ' -f 4)
        len=0x$(echo "$section" | cut -d ' ' -f 5)
        if [ "$M3_ISA" = "x86_64" ] || [ "$M3_ISA" = "riscv64" ]; then
            bytes=8
        else
            bytes=4
        fi
        echo "Constructors in $file ($off : $len):"
        if [ "$off" != "0x" ]; then
            od -t x$bytes "$file" -j "$off" -N "$len" -v -w$bytes | grep ' ' | while read -r line; do
                addr=${line#* }
                "${crossprefix}nm" -C -l "$file" 2>/dev/null | grep -m 1 "$addr"
            done
        fi
        ;;

    dis=*)
        "${crossprefix}objdump" -dC "$bindir/${cmd#dis=}" | less
        ;;

    elf=*)
        "${crossprefix}readelf" -aW "$bindir/${cmd#elf=}" | c++filt | less
        ;;

    list)
        echo "Start of section .text:"
        while IFS= read -r -d '' l; do
            "${crossprefix}readelf" -S "$build/bin/$l" | \
                grep " \.text " | awk "{ printf(\"%20s: %s\n\",\"$l\",\$5) }"
        done < <(find "$build/bin" -type f \! \( -name "*.o" -o -name "*.a" \) -printf "%f\0") | sort -k 2
        ;;

    macros=*)
        ( cd "${cmd#macros=}" && \
            cargo rustc "${rust_target_args[@]}" \
                --profile=check -- -Zunpretty=expanded 2>/dev/null | less )
        ;;

    nma=*)
        "${crossprefix}nm" -SCn "$bindir/${cmd#nma=}" | less
        ;;

    nms=*)
        "${crossprefix}nm" -SC --size-sort "$bindir/${cmd#nms=}" | less
        ;;

    straddr=*)
        binary=$bindir/${cmd#straddr=}
        str=$script
        echo "Strings containing '$str' in $binary:"
        # find base address of .rodata
        base=$("${crossprefix}readelf" -S "$binary" | grep .rodata | \
            xargs | cut -d ' ' -f 5)
        # find section number of .rodata
        section=$("${crossprefix}readelf" -S "$binary" | grep .rodata | \
            sed -e 's/.*\[\s*\([[:digit:]]*\)\].*/\1/g')
        # grep for matching lines, prepare for better use of awk and finally add offset to base
        "${crossprefix}readelf" -p "$section" "$binary" | grep "$str" | \
            sed 's/^ *\[ *\([[:xdigit:]]*\)\] *\(.*\)$/0x\1 \2/' | \
            awk '{ printf("0x%x: %s %s %s %s %s %s\n",0x'"$base"' + strtonum($1),$2,$3,$4,$5,$6,$7) }'
        ;;

    # -- file system --

    mkfs=*)
        "$tooldir/mkm3fs" "$build/${cmd#mkfs=}" "$script" "$@"
        ;;

    shfs=*)
        "$tooldir/shm3fs" "$build/${cmd#shfs=}" "$script" "$@"
        ;;

    fsck=*)
        "$tooldir/m3fsck" "$build/${cmd#fsck=}" "$script"
        ;;

    exfs=*)
        "$tooldir/exm3fs" "$build/${cmd#exfs=}" "$script"
        ;;

    # -- maintenance --

    checkboot)
        while IFS= read -r -d '' f; do
            xmllint --schema misc/boot.xsd --noout "$f" > /dev/null
        done < <(find boot -type f -print0)
        ;;

    clippy)
        while IFS= read -r -d '' f; do
            # vmtest only works on RISC-V
            if [ "$M3_ISA" != "riscv64" ] && [[ "$f" =~ "vmtest" ]]; then
                continue
            fi
            run_clippy "$f"
        done < <(find src tools -mindepth 2 -name Cargo.toml -print0)
        ;;

    clippy=*)
        run_clippy "${cmd#clippy=}/Cargo.toml"
        ;;

    doc)
        for lib in src/libs/rust/*; do
            if [ -d "$lib" ]; then
                ( cd "$lib" && cargo doc "${rust_target_args[@]}" )
            fi
        done
        echo "Documentation generated at file://$root/$build/rust/$RUST_TARGET/doc/m3/index.html"
        ;;

    fmt)
        while IFS= read -r -d '' f; do
            if [[ "$f" =~ "src/m3lx" ]]; then
                continue
            fi
            if [ "$(basename "$f")" != "build.py" ]; then
                if [[ "$f" =~ "src/libs/musl" ]] && [[ ! "$f" =~ "src/libs/musl/m3" ]]; then
                    continue
                fi
                if [[ "$f" =~ "src/libs/flac" ]] || [[ "$f" =~ "src/apps/bsdutils" ]] ||
                    [[ "$f" =~ "src/libs/leveldb" ]] || [[ "$f" =~ "src/libs/axieth" ]]; then
                    continue
                fi
            fi

            echo "Formatting $f..."
            case "$f" in
                *.cc|*.h)
                    clang-format -i "$f"
                    ;;
                */Cargo.toml)
                    find "$(dirname "$f")/src" -name "*.rs" -print0 | xargs -0 rustfmt
                    ;;
                *.py)
                    autopep8 --global-config .python-format -i "$f"
                    ;;
            esac
        done < <(find src tools -mindepth 2 \( -name Cargo.toml -or \
                                               -name "*.py" -or \
                                               -name "*.cc" -or \
                                               -name "*.h" \) -print0)
        ;;

    # -- M³Linux --

    mklx|mkbbl|genlxcc)
        ./src/m3lx/build.sh "$crossname" "$crossdir" "$cmd" "$script" "$@"
        ;;
esac
