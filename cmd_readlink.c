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

FORWARD(readlink);

#if !FBADB_MAIN
int
readlink_main(const struct cmd_readlink_info* info)
{
    struct cleanup* cl = NULL;
    char* buf = NULL;
    size_t bufsz = 64;
    ssize_t rc;

    do {
        bufsz *= 2;
        if (bufsz > (size_t) SSIZE_MAX)
            die(EINVAL, "readlink path too long");

        if (cl) {
            free(buf);
            cleanup_forget(cl);
        }

        cl = cleanup_allocate();
        buf = malloc(bufsz);
        if (buf == NULL)
            die_oom();
        cleanup_commit(cl, free, buf);
        rc = readlink(info->link, buf, bufsz);
    } while (rc > 0 && rc == bufsz);

    if (rc < 0)
        die(errno, "%s", strerror(errno));

    if (fwrite(buf, 1, rc, stdout) != rc)
        die_errno("fwrite");

    return 0;
}
#endif
