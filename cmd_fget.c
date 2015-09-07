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
#include "child.h"
#include "peer.h"
#include "xfer.h"

int
fget_main(const struct cmd_fget_info* info)
{
    const char* local = info->local ?: ".";

    struct start_peer_info spi = {
        .cwd = info->cwd,
        .adb = info->adb,
        .transport = info->transport,
        .user = info->user,
    };

    struct cmd_xfer_stub_info xilocal = {
        .mode = "recv",
        .filename = local,
        .desired_basename = xbasename(info->remote),
        .xfer = info->xfer,
    };

    struct cmd_xfer_stub_info xiremote = {
        .mode = "send",
        .filename = info->remote,
        .xfer = info->xfer,
    };

    return xfer_handle_command(&spi, &xilocal, &xiremote);
}
