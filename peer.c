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
#include "peer.h"

struct child*
start_peer(
    const struct start_peer_info* spi,
    const char* stub_command,
    struct strlist* stub_arguments)
{
    SCOPED_RESLIST(rl);

    struct strlist* stub_argv = strlist_new();
    strlist_append(stub_argv, stub_command);
    strlist_xfer(stub_argv, stub_arguments);

    struct cmd_rcmd_info rcmdi;
    memset(&rcmdi, 0, sizeof (rcmdi));
    rcmdi.adb = spi->adb;
    rcmdi.transport = spi->transport;
    rcmdi.user = spi->user;
    rcmdi.cwd = spi->cwd;
    rcmdi.command = "fb-adb";
    rcmdi.args = strlist_to_argv(stub_argv);
    rcmdi.shex.exename = "/proc/self/exe";

    struct strlist* stub_args = strlist_new();
    strlist_append(stub_args, orig_argv0);
    strlist_append(stub_args, "rcmd");
    strlist_xfer(stub_args,
                 make_args_cmd_rcmd(
                     CMD_ARG_ALL,
                     &rcmdi));

    struct child_start_info csi = {
        .flags = (CHILD_INHERIT_STDERR),
        .exename = my_exe(),
        .argv = strlist_to_argv(stub_args),
    };

    WITH_CURRENT_RESLIST(rl->parent);
    return child_start(&csi);
}
