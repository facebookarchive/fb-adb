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

extern int stub_main(int, const char**);

#if FBADB_MAIN
extern int shex_main(int, const char**);
extern int shex_main_rcmd(int, const char**);
#endif

#ifndef __ANDROID__
static void
view_with_pager(const char* filename)
{
    size_t qnamesz = 0;
    lim_shellquote(filename, &qnamesz, NULL, 0);
    char* qname = xalloc(qnamesz);
    size_t pos = 0;
    lim_shellquote(filename, &pos, qname, qnamesz);
    system(xaprintf("%s %s",
                    getenv("PAGER") ?: "less",
                    qname));
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
    } else if (!strcmp(prgarg, "help") ||
               !strcmp(prgarg, "-h") ||
               !strcmp(prgarg, "--help"))
    {
        usage();
        return 0;
    } else if (!strcmp(prgarg, "--version")) {
        printf("fb-adb %s\n", PACKAGE_VERSION);
        return 0;
    } else {
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
