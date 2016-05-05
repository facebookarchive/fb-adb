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
        .io[STDIN_FILENO] = ( spi->specified_io
                              ? spi->io[STDIN_FILENO]
                              : CHILD_IO_PIPE ),
        .io[STDOUT_FILENO] = ( spi->specified_io
                               ? spi->io[STDOUT_FILENO]
                               : CHILD_IO_PIPE ),
        .io[STDERR_FILENO] = CHILD_IO_RECORD,
        .exename = my_exe(),
        .argv = strlist_to_argv(local_self_args),
    };

    WITH_CURRENT_RESLIST(rl->parent);
    struct child* c = child_start(&csi);
    install_child_error_converter(c);
    return c;
}

static void
send_file_to_device_pre_exec(void* data)
{
    int fd = (intptr_t) data;
    if (dup2(fd, STDIN_FILENO) == -1)
        die_errno("dup2");
}

void
send_file_to_device(
    const struct adb_opts* adb,
    const struct transport_opts* transport,
    const struct user_opts* user,
    int fd,
    const char* device_file_name,
    mode_t mode)
{
    SCOPED_RESLIST(rl);

    dbg("sending file to device: remote name [%s]",
        device_file_name);

    struct strlist* args = strlist_new();
    strlist_append(args, orig_argv0);
    strlist_append(args, "fput");

    struct cmd_fput_info fpi = {
        .adb = *adb,
        .transport = *transport,
        .user = *user,
        .xfer.write_mode = "atomic",
        .xfer.mode = xaprintf("%o", mode),
        .local = "-",
        .remote = device_file_name,
    };

    strlist_xfer(args, make_args_cmd_fput(CMD_ARG_ALL, &fpi));

    struct child_start_info csi = {
        .io[STDIN_FILENO] = CHILD_IO_DEV_NULL,
        .io[STDOUT_FILENO] = CHILD_IO_DEV_NULL,
        .io[STDERR_FILENO] = CHILD_IO_RECORD,
        .pre_exec = send_file_to_device_pre_exec,
        .pre_exec_data = (void*) (intptr_t) fd,
        .exename = my_exe(),
        .argv = strlist_to_argv(args),
    };

    struct child* child = child_start(&csi);
    install_child_error_converter(child);
    int exit_code = child_status_to_exit_code(child_wait(child));
    if (exit_code != 0)
        die(ECOMM, "failed sending file to device");
}
