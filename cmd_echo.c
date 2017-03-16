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
#include "util.h"
#include "autocmd.h"
#include "fs.h"

#if !FBADB_MAIN

int
_echo_main(const struct cmd__echo_info* info)
{
    char buf[128];
    ssize_t nr_read;
    while ((nr_read = xread(STDIN_FILENO, buf, sizeof (buf))) > 0) {
        write_all(STDOUT_FILENO, buf, nr_read);
    }
    return 0;
}

#endif
