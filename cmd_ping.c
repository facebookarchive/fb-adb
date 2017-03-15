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
#include <sys/time.h>
#include "util.h"
#include "autocmd.h"
#include "peer.h"
#include "fs.h"

static
void
ping(struct child* peer)
{
    char csend = '.';
    write_all(peer->fd[STDIN_FILENO]->fd, &csend, sizeof (csend));
    char crecv;
    if (!read_all(peer->fd[STDOUT_FILENO]->fd, &crecv, sizeof (crecv)))
        die(EINVAL, "remote did not echo ping");
    if (csend != crecv)
        die(EINVAL, "child replied with wrong pong byte");
}

int
ping_main(const struct cmd_ping_info* info)
{
    struct start_peer_info spi = {
        .adb = info->adb,
        .transport = info->transport,
        .specified_io = true,
        .io[STDIN_FILENO] = CHILD_IO_PIPE,
        .io[STDOUT_FILENO] = CHILD_IO_PIPE,
    };
    struct child* peer = start_peer(
        &spi, strlist_from_argv(ARGV("_echo")));
    ping(peer);
    double time_ping = seconds_since_epoch();
    ping(peer);
    double time_pong = seconds_since_epoch();
    xprintf(xstdout, "%gms", (time_pong - time_ping) * 1000.0);
    return 0;
}

