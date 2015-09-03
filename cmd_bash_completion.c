/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in
 *  the LICENSE file in the root directory of this source tree. An
 *  additional grant of patent rights can be found in the PATENTS file
 *  in the same directory.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include "util.h"
#include "autocmd.h"

#if FBADB_MAIN
static const char bash_completion[] = {
#include "bash_completion.inc"
};

int
bash_completion_main(const struct cmd_bash_completion_info* info)
{
    write_all(STDOUT_FILENO, bash_completion, sizeof (bash_completion));
    return 0;
}
#endif
