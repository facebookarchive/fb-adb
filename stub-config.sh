#!/bin/bash
# Copyright (c) 2014, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in
# the LICENSE file in the root directory of this source tree. An
# additional grant of patent rights can be found in the PATENTS file
# in the same directory.
#
arch=$1
shift
srcdir=
declare -a cfgopts
for opt in "$@"; do
    if [[ $opt = --srcdir=* ]]; then
        srcdir=${opt:9}/..
        cfgopts+=(--srcdir="$srcdir")
    elif [[ $opt = 'CC='* ]]; then
        # Stub will choose CC for cross-compile
        unset CC
    else
        cfgopts+=("$opt")
    fi
done
exec $srcdir/configure \
     --build="$($srcdir/config.guess)" --host=$arch \
     BUILD_STUB=1 \
     "${cfgopts[@]}"
