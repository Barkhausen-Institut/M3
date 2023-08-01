#!/bin/sh

while read -r line; do
    if [ "$line" = "" ]; then
        break
    fi
    echo "$line"
done | "$@" >/dev/null 2>/dev/null
