#!/bin/bash
# Copyright (c) 2014, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in
# the LICENSE file in the root directory of this source tree. An
# additional grant of patent rights can be found in the PATENTS file
# in the same directory.
#

#
# This file takes a list of stub names on its command line and
# writes to stdout the contents of the corresponding stubs.c.
#
set -euo pipefail
: ${XXD=xxd}

cat <<EOF
#include <stdint.h>
#include "stubs.h"

EOF

for stub in "$@"; do
    cname=${stub%/stub}
    cname=${cname//-/_}
    printf 'static const uint8_t %s[] = {\n' "$cname"
    $XXD -i < $stub
    printf '};\n\n'
done

printf 'const struct fbadb_stub stubs[] = {\n'
for stub in "$@"; do
    cname=${stub%/stub}
    cname=${cname//-/_}
    printf '  { %s, sizeof(%s) },\n' "$cname" "$cname"
done
printf '};\n\n'
printf 'const size_t nr_stubs=%s;\n' $#
