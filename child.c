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
#include <errno.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include "child.h"

struct internal_child_info {
    int flags;
    const struct child_start_info* csi;
    int* childfd;
    int pty_slave;
};

__attribute__((noreturn))
static void
child_child_1(void* arg)
{
    struct internal_child_info* ci = arg;
    if (ci->flags & CHILD_SETSID)
        if (setsid() == (pid_t) -1)
            die_errno("setsid");

    if (ci->pty_slave != -1) {
        if (ioctl(ci->pty_slave, TIOCSCTTY, 0) == -1)
            die_errno("TIOCSCTTY");
        if (tcsetpgrp(ci->pty_slave, getpid()) == -1)
            die_errno("tcsetpgrp");
    }

    /* dup2 resets O_CLOEXEC */
    for (int i = 0; i < 3; ++i)
        if (dup2(ci->childfd[i], i) == -1)
            die_errno("dup2(%d->%d)", ci->childfd[i], i);

    sigset_t blocked;
    sigemptyset(&blocked);
    sigprocmask(SIG_SETMASK, &blocked, NULL);
    execvp(ci->csi->exename, (char**) ci->csi->argv);
    die_errno("execvp(\"%s\")", ci->csi->exename);
}

__attribute__((noreturn))
static void
child_child(struct internal_child_info* ci)
{
    struct errinfo ei = { 0 };
    ei.want_msg = true;
    if (!catch_error(child_child_1, ci, &ei))
        abort();

    fprintf(stderr, "%s: %s\n", ei.prgname, ei.msg);
    fflush(stderr);
    _exit(127); // Do not allow errors to propagate further
}

static void
child_cleanup(void* arg)
{
    struct child* child = arg;
    if (!child->dead_p) {
        if (child->pty_master == NULL) {
            /* In the pty case, the system's automatic SIGHUP should
             * take care of the killing.  */
            int sig = child->deathsig ?: SIGTERM;
            pid_t child_pid = child->pid;
            if (sig < 0) {
                /* Send to process group instead */
                sig = -sig;
                child_pid = -child_pid;
            }

            if (kill(child->pid, SIGTERM) < 0 && errno != ESRCH)
                die_errno("kill(%d)", (int) child->pid);
        }

        child_wait(child);
    }
}

struct child*
child_start(const struct child_start_info* csi)
{
    struct child* child = xcalloc(sizeof (*child));
    struct cleanup* cl_waiter = cleanup_allocate();
    SCOPED_RESLIST(rl_local);

    int flags = csi->flags;
    int pty_master = -1;
    int pty_slave = -1;

    if (flags & (CHILD_PTY_STDIN |
                 CHILD_PTY_STDOUT |
                 CHILD_PTY_STDERR |
                 CHILD_CTTY))
    {
        flags |= (CHILD_CTTY | CHILD_SETSID);
    }

    if (flags & CHILD_CTTY) {
        pty_master = xopen("/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC, 0);
        if (grantpt(pty_master) || unlockpt(pty_master))
            die_errno("grantpt/unlockpt");

#ifdef HAVE_PTSNAME
        char* pty_slave_name = xstrdup(ptsname(pty_master));
#else
        int pty_slave_num;
        if (ioctl(pty_master, TIOCGPTN, &pty_slave_num) != 0)
            die_errno("TIOCGPTN");

        char* pty_slave_name = xaprintf("/dev/pts/%d", pty_slave_num);
#endif
        pty_slave = xopen(pty_slave_name, O_RDWR | O_NOCTTY | O_CLOEXEC, 0);

        if (csi->pty_setup)
            csi->pty_setup(pty_master, pty_slave, csi->pty_setup_data);
    }

    int childfd[3];
    int parentfd[3];

    if (flags & CHILD_PTY_STDIN) {
        childfd[0] = xdup(pty_slave);
        parentfd[0] = xdup(pty_master);
    } else {
        xpipe(&childfd[0], &parentfd[0]);
    }

    if (flags & CHILD_PTY_STDOUT) {
        childfd[1] = xdup(pty_slave);
        parentfd[1] = xdup(pty_master);
    } else {
        xpipe(&parentfd[1], &childfd[1]);
    }

    // If child has a pty for both stdout and stderr, from our POV, it
    // writes only to stdout.
    if ((flags & CHILD_PTY_STDERR) && (flags & CHILD_PTY_STDOUT))
        flags |= CHILD_MERGE_STDERR;

    if (flags & CHILD_MERGE_STDERR) {
        childfd[2] = xdup(childfd[1]);
        parentfd[2] = xopen("/dev/null", O_RDONLY, 0);
    } else if (flags & CHILD_PTY_STDERR) {
        childfd[2] = xdup(pty_slave);
        parentfd[2] = xdup(pty_master);
    } else if (flags & CHILD_INHERIT_STDERR) {
        childfd[2] = xdup(2);
    } else {
        xpipe(&parentfd[2], &childfd[2]);
    }

    reslist_pop_nodestroy(rl_local);
    child->flags = flags;
    child->deathsig = csi->deathsig;
    if (pty_master != -1)
        child->pty_master = fdh_dup(pty_master);
    child->fd[0] = fdh_dup(parentfd[0]);
    child->fd[1] = fdh_dup(parentfd[1]);
    if ((flags & CHILD_INHERIT_STDERR) == 0)
        child->fd[2] = fdh_dup(parentfd[2]);

    pid_t child_pid = fork();

    if (child_pid == -1)
        die_errno("fork");

    if (child_pid == 0) {
        struct internal_child_info ci = {
            .flags = flags,
            .csi = csi,
            .pty_slave = pty_slave,
            .childfd = childfd,
        };

        child_child(&ci);
    }

    child->pid = child_pid;
    cleanup_commit(cl_waiter, child_cleanup, child);
    return child;
}

int
child_wait(struct child* child)
{
    if (!child->dead_p) {
        int ret;
        do {
            ret = waitpid(child->pid, &child->status, 0);
        } while (ret < 0 && errno == EINTR);

        if (ret < 0)
            die_errno("waitpid(%u)", (unsigned) child->pid);

        child->dead_p = true;
    }

    return child->status;
}
