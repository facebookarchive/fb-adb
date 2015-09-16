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
#include <sys/types.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include "util.h"
#include "strutil.h"
#include "cmd.h"
#include "autocmd.h"
#include "timestamp.h"
#include "fs.h"

static bool
word_follows_adb_arg_p(const char* p)
{
    for (; *p; ++p) {
        if (strchr("spHP", *p)) {
            if (*(p+1) == '\0')
                return true;

            return false;
        }
    }

    return false;
}

static bool
adb_arg_p(char** argv, unsigned i)
{
    if (argv[i] == NULL)
        return false;

    if (argv[i][0] == '-' && argv[i][1] == 'h')
        return false;

    if (argv[i][0] == '-' &&
        argv[i][1] == '-' &&
        argv[i][2] != '\0')
    {
        return false;
    }

    if (i > 1 && !strcmp(argv[i-1], "--"))
        return false;

    if (argv[i][0] == '-')
        return true;

    /* Catch FOO in pairs like -s FOO */
    if (i > 1 &&
        argv[i-1][0] == '-' &&
        word_follows_adb_arg_p(argv[i-1]))
    {
        return true;
    }

    return false;
}

int
real_main(int argc, char** argv)
{
    unsigned nr_adb_args = 0;
    while (adb_arg_p(argv, nr_adb_args + 1))
        nr_adb_args += 1;

    unsigned non_adb_off = 1 + nr_adb_args;
    char* prgarg = argv[non_adb_off];

    if (prgarg == NULL)
        die(EINVAL, "no sub-command given. Use --help for help.");

    if (!strcmp(prgarg, "--version")) {
#ifdef HAVE_GIT_STAMP
        xfprintf(xstdout, "fb-adb %s git:%s\n",
                 PACKAGE_VERSION,
                 git_stamp);
#else
        xprintf(xstdout, "fb-adb %s\n", PACKAGE_VERSION);
#endif
        return 0;
    }

    if (!strcmp(prgarg, "-h") || !strcmp(prgarg, "--help"))
        prgarg = "help";

    const struct cmd* cmd = &autocmds[0];
    while (cmd->main != NULL) {
        if (!strcmp(cmd->name, prgarg))
            break;
        cmd++;
    }

    if (cmd->main != NULL) {
        char* new_argv0 = xaprintf("%s %s", prgname, prgarg);
        set_prgname(new_argv0);
        argv[0] = new_argv0;
        memmove(&argv[non_adb_off],
                &argv[non_adb_off+1],
                sizeof (*argv) * (argc - nr_adb_args - 1));
        return cmd->main(argc - 1, (const char**) argv);
    }

    sigprocmask(SIG_SETMASK, &orig_sigmask, NULL);
    execvp("adb", argv);
    die(EINVAL, "could not exec adb: %s", strerror(errno));
}
