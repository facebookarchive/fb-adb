#include <errno.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include "child.h"

struct child*
child_start(const struct child_start_info* csi)
{
    SCOPED_RESLIST(rl_local);

    int flags = csi->flags;
    int pty_master = -1;
    int pty_slave = -1;

    if (flags & (CHILD_PTY_STDIN |
                 CHILD_PTY_STDOUT |
                 CHILD_PTY_STDERR |
                 CHILD_CTTY))
    {
        pty_master = xopen("/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC, 0);
        if (grantpt(pty_master) || unlockpt(pty_master))
            die_errno("grantpt/unlockpt");

        int pty_slave_num;
        if (ioctl(pty_master, TIOCGPTN, &pty_slave_num) != 0)
            die_errno("TIOCGPTN");

        char* pty_slave_name = xaprintf("/dev/pts/%d", pty_slave_num);
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

    if ((flags & CHILD_PTY_STDERR) && (flags & CHILD_PTY_STDOUT)) {
        // If child has a pty for both stdout and stderr, from our
        // POV, it writes only to stdout.
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

    pid_t child_pid = fork();

    if (child_pid == -1)
        die_errno("fork");

    if (child_pid == 0) {
        if (pty_slave != -1) {
            if (setsid() == (pid_t) -1)
                die_errno("setsid");
            if (ioctl(pty_slave, TIOCSCTTY, pty_slave) == -1)
                die_errno("TIOCSCTTY");
            if (tcsetpgrp(pty_slave, getpid()) == -1)
                die_errno("tcsetpgrp");
        }

        /* dup2 resets O_CLOEXEC */
        for (int i = 0; i < 3; ++i)
            if (dup2(childfd[i], i) == -1)
                die_errno("dup2(%d->%d)", childfd[i], i);

        sigset_t blocked;
        sigemptyset(&blocked);
        sigprocmask(SIG_SETMASK, &blocked, NULL);
        execvp(csi->exename, (char**) csi->argv);
        die_errno("execvp(\"%s\")", csi->exename);
    }

    reslist_pop_nodestroy();

    struct child* child = xcalloc(sizeof (*child));
    child->pid = child_pid;
    if (pty_master != -1)
        child->pty_master = fdh_dup(pty_master);
    child->fd[0] = fdh_dup(parentfd[0]);
    child->fd[1] = fdh_dup(parentfd[1]);
    if ((flags & CHILD_INHERIT_STDERR) == 0)
        child->fd[2] = fdh_dup(parentfd[2]);

    return child;
}
