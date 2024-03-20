#!/bin/sh

MAKE_ARGS="-j"$(nproc)

usage() {
    echo "Usage: $1 (x86_64|riscv64|riscv32) ..." >&2
    exit
}

if [ $# -lt 1 ]; then
    usage "$0"
fi

ARCH="$1"
shift
if [ "$ARCH" != "x86_64" ] && [ "$ARCH" != "riscv64" ] && [ "$ARCH" != "riscv32" ]; then
    usage "$0"
fi

ROOT=$(dirname "$(readlink -f "$0")")
DIST="$(readlink -f "$ROOT/..")/build/cross-$ARCH"

if [ -f "$DIST/.config" ] && [ "$(cmp "$DIST/.config-origin" "config-$ARCH" 2>/dev/null)" != "" ]; then
    printf "\e[1mWARNING: %s/.config-origin and config-%s differ\n\e[0m" "$DIST" "$ARCH"
    printf "This probably indicates that config-%s was updated and you should rebuild.\n" "$ARCH"
    printf "Do you want to rebuild completely (r), update to the new config (u), or continue"
    printf " with the potentially outdated %s/.config (c)? " "$DIST"
    read -r choice
    case $choice in
        r) rm -rf "$DIST" ;;
        u) rm -f "$DIST/.config" ;;
        c) ;;
        *) exit ;;
    esac
fi

if [ ! -f "$DIST/.config" ]; then
    ( cd buildroot && make O="$DIST" "$MAKE_ARGS" defconfig "BR2_DEFCONFIG=../config-$ARCH" )
    cp "config-$ARCH" "$DIST/.config-origin"
fi

( cd buildroot && make O="$DIST" "$MAKE_ARGS" "$@" )
