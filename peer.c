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
#include <assert.h>
#include "peer.h"

struct child*
start_peer(
    const struct start_peer_info* spi,
    struct strlist* stub_arguments)
{
    SCOPED_RESLIST(rl);

    struct cmd_rcmd_self_info rcmdi;
    memset(&rcmdi, 0, sizeof (rcmdi));
    rcmdi.adb = spi->adb;
    rcmdi.transport = spi->transport;
    rcmdi.user = spi->user;
    rcmdi.cwd = spi->cwd;
    rcmdi.args = strlist_to_argv(stub_arguments);

    struct strlist* local_self_args = strlist_new();
    strlist_append(local_self_args, orig_argv0);
    strlist_xfer(local_self_args,
                 make_args_cmd_rcmd_self(
                     CMD_ARG_ALL | CMD_ARG_NAME,
                     &rcmdi));

    struct child_start_info csi = {
        .io[STDIN_FILENO] = CHILD_IO_PIPE,
        .io[STDOUT_FILENO] = CHILD_IO_PIPE,
        .io[STDERR_FILENO] = CHILD_IO_RECORD,
        .exename = my_exe(),
        .argv = strlist_to_argv(local_self_args),
    };

    WITH_CURRENT_RESLIST(rl->parent);
    struct child* c = child_start(&csi);
    install_child_error_converter(c);
    return c;
}
