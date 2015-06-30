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
#include "cmd_shex.h"
#include "cmd_stub.h"
#include "cmd_logw.h"
#include "cmd_readlink.h"
#include "timestamp.h"

#ifndef __ANDROID__
static void
view_with_pager(const char* filename)
{
    system(xaprintf("%s %s",
                    getenv("PAGER") ?: "less",
                    xshellquote(filename)));
}
#endif

static void
usage(void)
{
    FILE* out = stdout;
#ifndef __ANDROID__
    const char* tmpf_name = NULL;
    if (isatty(1)) {
        out = xnamed_tempfile(&tmpf_name);
        allow_inherit(fileno(out));
    }
#endif

    fprintf(out, "%s %s - Enhanced ADB\n", prgname, PACKAGE_VERSION);
    fprintf(out, "\n");
    fprintf(out, "  %s shell [CMD ARGS...] - Improved adb shell.\n", prgname);
    fprintf(out, "\n");
    fprintf(out, "  %s rcmd CMD [ARGS...] - Run commands directly, "
            "without\n", prgname);
    fprintf(out, "    using the shell.\n");
    fprintf(out, "\n");
    fprintf(out, "  Use %s rcmd -h for additional help.\n", prgname);
    fprintf(out, "  Other commands forward to adb. See below.\n");
    fprintf(out, "\n");
    fflush(out);
    system(xaprintf("adb help >& %d 2>&1", fileno(out)));

#ifndef __ANDROID__
    if (tmpf_name) {
        view_with_pager(tmpf_name);
    }
#endif
}

#define DECLARE_FORWARDER(name)                                 \
    int name##_wrapper_main(int argc, const char** argv)        \
    {                                                           \
        return shex_wrapper(                                    \
            #name,                                              \
            name##_opts,                                        \
            name##_longopts,                                    \
            name##_usage,                                       \
            argv);                                              \
    }

DECLARE_FORWARDER(logw);
DECLARE_FORWARDER(readlink);

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

    int (*sub_main)(int, const char**) = NULL;
    if (!strcmp(prgarg, "stub")) {
        sub_main = stub_main;
#if FBADB_MAIN
    } else if (!strcmp(prgarg, "shellx") || !strcmp(prgarg, "sh")) {
        sub_main = shex_main;
    } else if (!strcmp(prgarg, "shell") &&
               !getenv("ADB_SHELL_OLD_BEHAVIOR"))
    {
        sub_main = shex_main;
    } else if (!strcmp(prgarg, "rcmd")) {
        sub_main = shex_main_rcmd;
#endif
    } else if (!strcmp(prgarg, "logw")) {
#if FBADB_MAIN
        sub_main = logw_wrapper_main;
#else
        sub_main = logw_main;
#endif
    } else if (!strcmp(prgarg, "readlink")) {
#if FBADB_MAIN
        sub_main = readlink_wrapper_main;
#else
        sub_main = readlink_main;
#endif
    } else if (!strcmp(prgarg, "help") ||
               !strcmp(prgarg, "-h") ||
               !strcmp(prgarg, "--help"))
    {
        usage();
        return 0;
    } else if (!strcmp(prgarg, "--version")) {
#ifdef HAVE_GIT_STAMP
        printf("fb-adb %s git:%s\n", PACKAGE_VERSION, git_stamp);
#else
        printf("fb-adb %s\n", PACKAGE_VERSION);
#endif
        return 0;
    } else {
        sigprocmask(SIG_SETMASK, &orig_sigmask, NULL);
        execvp("adb", argv);
        die(EINVAL, "could not exec adb: %s", strerror(errno));
    }

    char* new_argv0 = xaprintf("%s %s", prgname, prgarg);
    set_prgname(new_argv0);
    argv[0] = new_argv0;
    memmove(&argv[non_adb_off],
            &argv[non_adb_off+1],
            sizeof (*argv) * (argc - nr_adb_args - 1));
    return sub_main(argc - 1, (const char**) argv);
}
