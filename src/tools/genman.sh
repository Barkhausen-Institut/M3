#!/bin/sh

progs="basename cat cp csplit cut date dd dirname du echo expr factor false find fmt head join ln ls"
progs="$progs mkdir mktemp mv nl paste pathchk printenv printf pwd rm rmdir sleep split stat sync"
progs="$progs tee test touch tr true tsort uniq wc yes"

mkdir -p src/fs/default/man

for p in $progs; do
    for no in 1 6 8; do
        f=src/apps/bsdutils/src/$p/$p.$no
        if [ -f "$f" ]; then
            MANWIDTH=100 man --ascii -E ascii "$f" > "src/fs/default/man/$(basename -s ".$no" "$f").1";
        fi
    done
done
