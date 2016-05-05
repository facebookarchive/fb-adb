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
#include "json.h"

#if FBADB_MAIN

FORWARD(pidof);

#elif !defined(__linux__)

int
pidof_main(const struct cmd_pidof_info* info)
{
    die(EINVAL, "this command is supported only on Linux");
}

#else

int
pidof_main(const struct cmd_pidof_info* info)
{
    const char* name = info->name;
    DIR* procdir = xopendir("/proc");
    struct dirent* ent;
    unsigned long found_pid = 0;
    bool found = false;
    while ((ent = readdir(procdir)) != NULL) {
        SCOPED_RESLIST(rl);
        char* endptr = NULL;
        errno = 0;
        unsigned long pid = strtoul(ent->d_name, &endptr, 10);
        if (pid == 0 || errno != 0 || *endptr != '\0')
            continue;
        int cmdline_fd = try_xopen(xaprintf("/proc/%lu/cmdline", pid), O_RDONLY, 0);
        if (cmdline_fd == -1)
            continue;
        char* name = slurp_fd(cmdline_fd, NULL);
        if (strcmp(name, info->name) == 0) {
            if (found)
                die(EINVAL, "more than one process has name `%s'", name);
            found = true;
            found_pid = pid;
        }
    }

    if (!found)
        die(ENOENT, "no process has name `%s'", name);
    xprintf(xstdout, "%lu%s", found_pid, info->pidof.zero ? "" : "\n");
    xflush(xstdout);
    return 0;
}

#endif
