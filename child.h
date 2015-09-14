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
#pragma once
#include <stdint.h>
#include "util.h"

#define CHILD_CTTY (1<<0)
#define CHILD_SETSID (1<<1)

enum child_io_mode {
    CHILD_IO_DEV_NULL,
    CHILD_IO_PTY,
    CHILD_IO_PIPE,
    CHILD_IO_INHERIT,
    CHILD_IO_RECORD,
    CHILD_IO_DUP_TO_STDOUT,
};

struct child_start_info {
    int flags;
    const char* exename;
    const char* const* argv;
    const char* const* environ;
    enum child_io_mode io[3];
    void (*pre_exec)(void* data);
    void* pre_exec_data;
    void (*pty_setup)(int master, int slave, void* data);
    void* pty_setup_data;
    int deathsig;
    const char* child_chdir;
};

struct fdrecorder;
struct child {
    int flags;
    int deathsig;
    pid_t pid;
    int status;
    struct fdh* pty_master;
    struct fdh* fd[3];
    struct fdrecorder* recorder[3];
    unsigned dead : 1;
    unsigned skip_cleanup_wait : 1;
};

struct child* child_start(const struct child_start_info* csi);
int child_wait(struct child* c);
bool child_poll_death(struct child* c);
void child_kill(struct child* c, int signo);

struct child_communication {
    int status;
    size_t bytes_consumed; // Of data_for_child

    struct {
        uint8_t* bytes;
        size_t nr;
    } out[ARRAYSIZE(((struct child*)0)->fd) - 1];
};

struct child_communication* child_communicate(
    struct child* child,
    const void* data_for_child,
    size_t data_for_child_size);

bool child_status_success_p(int status);
int child_status_to_exit_code(int status);
char* massage_output(const void* buf, size_t nr_bytes);
