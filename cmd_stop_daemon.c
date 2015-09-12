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
#include "core.h"

FORWARD(stop_daemon);

#if !FBADB_MAIN
#include "stubdaemon.h"

int
stop_daemon_main(const struct cmd_stop_daemon_info* info)
{
    stop_daemon();
    return 0;
}
#endif
