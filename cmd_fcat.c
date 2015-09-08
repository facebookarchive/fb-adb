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

FORWARD(fcat);

#if !FBADB_MAIN
int
fcat_main(const struct cmd_fcat_info* info)
{
    size_t bufsz = 64*1024;
    uint8_t* buf = xalloc(bufsz);
    const char* const* files = info->files;
    while (files && *files) {
        SCOPED_RESLIST(rl);
        int fd = xopen(*files, O_RDONLY, 0);
        size_t nr_read;
        do {
            nr_read = read_all(fd, buf, bufsz);
            write_all(1, buf, nr_read);
        } while (nr_read > 0);
        ++files;
    }
    return 0;
}
#endif
