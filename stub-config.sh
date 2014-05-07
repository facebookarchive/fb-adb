#!/bin/bash
arch=$1
shift
srcdir=
declare -a cfgopts
for opt in "$@"; do
    if [[ $opt = --srcdir=* ]]; then
        srcdir=${opt:9}/..
        cfgopts+=(--srcdir="$srcdir")
    else
        cfgopts+=("$opt")
    fi
done
exec $srcdir/configure \
     --build="$($srcdir/config.guess)" --host=$arch \
     BUILD_STUB=1 \
     "${cfgopts[@]}"
