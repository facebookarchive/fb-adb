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
#include "fs.h"
#include "child.h"
#include "constants.h"
#include "dex.h"

FORWARD(rdex);

#if !FBADB_MAIN

int
rdex_main(const struct cmd_rdex_info* info)
{
    const char* dex_file_name = info->dexfile;
    compile_dex(dex_file_name);

    if (setenv("CLASSPATH", dex_file_name, 1) == -1)
        die_errno("setenv");

    if (info->classname[0] == '-')
        die(EINVAL, "class name cannot begin with '-'");

    execvp("app_process",
           (char* const*)
           ARGV_CONCAT(
               ARGV("app_process",
                    xdirname(dex_file_name),
                    info->classname),
               info->args ?: empty_argv));
    die_errno("execvp(\"app_process\", ...");
}
#endif
