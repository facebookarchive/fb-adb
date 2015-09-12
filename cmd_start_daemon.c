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
#include <arpa/inet.h>
#include <string.h>
#include "util.h"
#include "autocmd.h"
#include "fs.h"
#include "child.h"
#include "net.h"
#include "strutil.h"
#include "constants.h"

FORWARD(start_daemon);

#if !FBADB_MAIN
#include "stubdaemon.h"

int
start_daemon_main(const struct cmd_start_daemon_info* info)
{
    struct cmd_stub_info sinfo = {
        .stub.listen = true,
        .stub.daemonize = true,
        .stub.replace = true,
    };

    return stub_main(&sinfo);
}

#endif
