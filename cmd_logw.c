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
#include "cmd_logw.h"

const char logw_opts[] = "+:t:r:h";
const struct option logw_longopts[] = {
    { "help", no_argument, NULL, 'h' },
    { "tag", required_argument, NULL, 't' },
    { "priority", required_argument, NULL, 'r' },
    { 0 },
};

const char logw_usage[] = (
    "fb-adb logw [-r PRIORITY] [-t TAG] MESSAGE: write message to logcat\n"
    "\n"
    "  -r PRIORITY\n"
    "  --priority PRIORITY\n"
    "    Set logcat priority to PRIORITY.  PRIORITY is a case-insensitive\n"
    "    substring of \"verbose\", \"debug\", \"informational\",\n"
    "    \"warning\", \"error\", or \"fatal\".\n"
    "\n"
    "  -t TAG\n"
    "  --tag TAG\n"
    "    Set logcat tag to TAG.\n"
    "\n"
    "MESSAGE is any string.  It is interpreted as UTF-8.\n"\
    "\n"
    );

#if !FBADB_MAIN

#include <android/log.h>

static const char* log_levels[] = {
    // We use a prefix match, so make these long
    "verbose",
    "debug",
    "informational",
    "warning",
    "error",
    "fatal",
};

static void
tolower_inplace(char* s)
{
    for (;*s; ++s) {
        *s = tolower(*s);
    }
}

int
logw_main(int argc, const char** argv)
{
    const char* tag = "fb-adb-logw";
    int priority = ANDROID_LOG_INFO;

    for (;;) {
        int c = getopt_long(argc,
                             (char**) argv,
                             logw_opts,
                             logw_longopts,
                             NULL);

        if (c == -1)
            break;

        switch (c) {
            case 't':
                tag = optarg;
                break;
            case 'r':
                priority = -1;
                char* xprio = xstrdup(optarg);
                tolower_inplace(xprio);
                size_t xprio_len = strlen(xprio);
                for (unsigned i = 0; i < ARRAYSIZE(log_levels); ++i) {
                    if (!strncmp(xprio, log_levels[i], xprio_len)) {
                        priority = ANDROID_LOG_VERBOSE + i;
                        break;
                    }
                }

                if (priority == -1)
                    die(EINVAL, "invalid logging priority \"%s\"", optarg);

                break;
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
                fputs(logw_usage, stdout);
                return 0;
            default:
                abort();
        }
    }

    argc -= optind;
    argv += optind;

    size_t sz = 1;
    for (int i = 0; i < argc; ++i) {
        if (SATADD(&sz, sz, strlen(argv[i]) + 1))
            die(EINVAL, "argument list too long");
    }

    char* msg = xalloc(sz);
    char* pos = msg;
    for (int i = 0; i < argc; ++i) {
        size_t len = strlen(argv[i]);
        memcpy(pos, argv[i], len);
        pos += len;
        if (i != argc -1)
            *pos++ = ' ';
    }

    msg[sz-1] = '\0';
    int ret = __android_log_write(priority, tag, msg);
    if (ret < 0) {
        errno = -ret;
        die_errno("__android_log_write");
    }

    return 0;
}

#endif
