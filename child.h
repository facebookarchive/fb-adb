#pragma once
#include "util.h"

#define CHILD_PTY_STDIN  0x1
#define CHILD_PTY_STDOUT 0x2
#define CHILD_PTY_STDERR 0x4
#define CHILD_INHERIT_STDERR 0x8
#define CHILD_CTTY 0x10
#define CHILD_MERGE_STDERR 0x20

struct child_start_info {
    int flags;
    const char* exename;
    const char* const* argv;
    void (*pty_setup)(int master, int slave, void* data);
    void* pty_setup_data;
};

struct child {
    pid_t pid;
    struct fdh* pty_master;
    struct fdh* fd[3];
};

struct child* child_start(const struct child_start_info* csi);
