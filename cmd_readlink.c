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
#include "util.h"
#include "cmd_readlink.h"

const char readlink_opts[] = "+:h";
const struct option readlink_longopts[] = {
    { "help", no_argument, NULL, 'h' },
    { 0 },
};

const char readlink_usage[] = (
    "fb-adb readlink LINK: call readlink(2) on device\n"
    "\n"
    "LINK is the name of a symbolic link.\n"
    "Fail if LINK does not exist or is not a symbolic link.\n"
    "\n"
    );

#if !FBADB_MAIN

static void
cleanup_free_ptr(void* data)
{
    void** ptrptr = data;
    free(*ptrptr);
}

static void
readlink_impl(const char* link)
{
    SCOPED_RESLIST(rl);
    char* buf = NULL;
    size_t bufsz = 64;
    char* new_buf;
    ssize_t rc;

    cleanup_commit(cleanup_allocate(), cleanup_free_ptr, &buf);

    do {
        bufsz *= 2;
        if (bufsz > (size_t) SSIZE_MAX)
            die(EINVAL, "readlink path too long");
        new_buf = realloc(buf, bufsz);
        if (new_buf == NULL)
            die_oom();
        buf = new_buf;
        rc = readlink(link, buf, bufsz);
    } while (rc > 0 && rc == bufsz);

    if (rc < 0)
        die_errno("readlink");

    if (fwrite(buf, 1, rc, stdout) != rc)
        die_errno("fwrite");
}

int
readlink_main(int argc, const char** argv)
{
    for (;;) {
        int c = getopt_long(argc,
                            (char**) argv,
                            readlink_opts,
                            readlink_longopts,
                            NULL);

        if (c == -1)
            break;

        switch (c) {
            case ':':
                if (optopt == '\0') {
                    die(EINVAL, "missing argument for %s", argv[optind-1]);
                } else {
                    die(EINVAL, "missing argument for -%c", optopt);
                }
            case '?':
                if (optopt == '?') {
                    // Fall through to help
                } else if (optopt == '\0') {
                    die(EINVAL, "invalid option %s", argv[optind-1]);
                } else {
                    die(EINVAL, "invalid option -%c", (int) optopt);
                }
            case 'h':
                fputs(readlink_usage, stdout);
                return 0;
            default:
                abort();
        }
    }

    argc -= optind;
    argv += optind;

    if (argc != 1)
        die(EINVAL, "no LINK supplied");

    readlink_impl(argv[0]);
    return 0;
}

#endif
