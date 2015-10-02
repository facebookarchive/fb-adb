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
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "util.h"
#include "autocmd.h"
#include "argv.h"

#if FBADB_MAIN

FORWARD(logw);

#elif !defined(__ANDROID__)

int
logw_main(const struct cmd_logw_info* info)
{
    die(ENOSYS, "Android logcat not supported on this system");
}

#else

static const char* log_levels[] = {
    // We use a prefix match, so make these long
    "verbose",
    "debug",
    "informational",
    "warning",
    "error",
    "fatal",
};

#include <android/log.h>

static void
tolower_inplace(char* s)
{
    for (;*s; ++s) {
        *s = tolower(*s);
    }
}

int
logw_main(const struct cmd_logw_info* info)
{
    const char* tag = info->logw.tag ?: "fb-adb-logw";
    int priority = ANDROID_LOG_INFO;

    if (info->logw.priority) {
        priority = -1;
        char* xprio = xstrdup(info->logw.priority);
        tolower_inplace(xprio);
        size_t xprio_len = strlen(xprio);
        for (unsigned i = 0; i < ARRAYSIZE(log_levels) - 1; ++i) {
            if (!strncmp(xprio, log_levels[i], xprio_len)) {
                priority = ANDROID_LOG_VERBOSE + i;
                break;
            }
        }

        if (priority == -1)
            usage_error("unknown priority \"%s\"",
                        info->logw.priority);
    }

    const char* const* p;
    size_t sz = 1;

    for (p = info->message_parts; *p; ++p)
        if (SATADD(&sz, sz, strlen(*p) + 1))
            die(EINVAL, "argument list too long");

    char* msg = xalloc(sz);
    char* pos = msg;

    for (p = info->message_parts; *p; ++p) {
        const char* m = *p;
        size_t len = strlen(m);
        memcpy(pos, m, len);
        pos += len;
        if (pos - len != msg)
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
