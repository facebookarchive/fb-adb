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
#include "strutil.h"

#if FBADB_MAIN
static const char bash_completion[] = {
#include "bash_completion.inc"
};

int
bash_completion_main(const struct cmd_bash_completion_info* info)
{
    const char* fb_adb_binary = orig_argv0;
#ifdef HAVE_REALPATH
    // If argv0 isn't a relative or absolute path, assume we got it
    // from PATH and don't touch it.
    if (strchr(fb_adb_binary, '/'))
        fb_adb_binary = xrealpath(fb_adb_binary);
#endif
    char* argv0_line = xaprintf(
        ": ${_fb_adb:=%s}\n",
        xshellquote(fb_adb_binary));
    write_all(STDOUT_FILENO, argv0_line, strlen(argv0_line));
    write_all(STDOUT_FILENO, bash_completion, sizeof (bash_completion));
    return 0;
}
#endif
