#include <errno.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "child.h"

struct child*
child_start(int flags,
            const char* exename,
            const char* const* argv)
{
    SCOPED_RESLIST(rl_local);

    /* We need a tty to control the child even if the child doesn't
     * use the tty for its standard file descriptors.  */

    int pty_master = xopen("/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC, 0);
    if (grantpt(pty_master) || unlockpt(pty_master))
        die_errno("grantpt/unlockpt");

    int pty_slave_num;
    if (ioctl(pty_master, TIOCGPTN, &pty_slave_num) != 0)
        die_errno("TIOCGPTN");

    char* pty_slave_name = xaprintf("/dev/pts/%d", pty_slave_num);
    int pty_slave = xopen(pty_slave_name, O_RDWR | O_NOCTTY | O_CLOEXEC, 0);

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

    if (flags & CHILD_PTY_STDERR) {
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
        if (setsid() == (pid_t) -1)
            die_errno("setsid");

        if (flags & CHILD_NOCTTY)
            if (ioctl(pty_slave, TIOCSCTTY, pty_slave) == -1)
                die_errno("TIOCSCTTY");

        /* dup2 resets O_CLOEXEC */
        for (int i = 0; i < 3; ++i)
            if (dup2(childfd[i], i) == -1)
                die_errno("dup2(%d->%d)", childfd[i], i);

        execvp(exename, (char**) argv);
        die_errno("execvp(\"%s\")", exename);
    }

    reslist_pop_nodestroy();

    struct child* child = xcalloc(sizeof (*child));
    child->pid = child_pid;
    child->pty_master = fdh_dup(pty_master);
    child->fd[0] = fdh_dup(parentfd[0]);
    child->fd[1] = fdh_dup(parentfd[1]);
    if ((flags & CHILD_INHERIT_STDERR) == 0)
        child->fd[2] = fdh_dup(parentfd[2]);

    return child;
}
