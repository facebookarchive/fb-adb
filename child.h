#pragma once
#include "util.h"

#define CHILD_PTY_STDIN  0x1
#define CHILD_PTY_STDOUT 0x2
#define CHILD_PTY_STDERR 0x4

struct child {
    pid_t pid;
    struct fdh* pty_master;
    struct fdh* fd[3];
};

struct child* child_start(int flags,
                          const char* exename,
                          const char* const* argv);

