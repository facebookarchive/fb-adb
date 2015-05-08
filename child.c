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
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <assert.h>
#include <limits.h>
#include "child.h"
#include "net.h"

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

    /* dup2 resets O_CLOEXEC */
    for (int i = 0; i < 3; ++i)
        if (dup2(ci->childfd[i], i) == -1)
            die_errno("dup2(%d->%d)", ci->childfd[i], i);

    if (ci->csi->child_chdir && chdir(ci->csi->child_chdir) == -1)
        die_errno("chdir");

    if (ci->flags & CHILD_SETSID)
        if (setsid() == (pid_t) -1)
            die_errno("setsid");

    if (ci->pty_slave != -1) {
        if (ioctl(ci->pty_slave, TIOCSCTTY, 0) == -1)
            die_errno("TIOCSCTTY");
        if (tcsetpgrp(ci->pty_slave, getpid()) == -1)
            die_errno("tcsetpgrp");
    }

    for (int i = 0; i < NSIG; ++i)
        signal(i, SIG_DFL);

    sigset_t no_signals;
    VERIFY(sigemptyset(&no_signals) == 0);
    VERIFY(sigprocmask(SIG_SETMASK, &no_signals, NULL) == 0);

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
    if (!child->dead) {
        if (child->pty_master == NULL) {
            int sig = child->deathsig ?: SIGTERM;
            pid_t child_pid = child->pid;
            if (sig < 0) {
                /* Send to process group instead */
                sig = -sig;
                child_pid = -child_pid;
            }

            if (kill(child->pid, SIGTERM) < 0 && errno != ESRCH)
                die_errno("kill(%d)", (int) child->pid);

        } else {
            /* In the pty case, the system's automatic SIGHUP should
             * take care of the killing.  */
            fdh_destroy(child->pty_master);
        }

        if (!child->skip_cleanup_wait && !signal_quit_in_progress)
            child_wait(child);
    }
}

struct child*
child_start(const struct child_start_info* csi)
{
    struct child* child = xcalloc(sizeof (*child));
    struct cleanup* cl_waiter = cleanup_allocate();
    SCOPED_RESLIST(rl);

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
        // Yes, yes, ptsname is not thread-safe.  We're
        // single-threaded.
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

    if (flags & CHILD_SOCKETPAIR_STDIO) {
        flags &= ~(CHILD_PTY_STDIN | CHILD_PTY_STDOUT);
        xsocketpair(AF_UNIX, SOCK_STREAM, 0, &childfd[0], &parentfd[0]);
        childfd[1] = xdup(childfd[0]);
        parentfd[1] = xdup(parentfd[0]);
    } else {
        if (flags & CHILD_PTY_STDIN) {
            childfd[0] = xdup(pty_slave);
            parentfd[0] = xdup(pty_master);
        } else if (flags & CHILD_NULL_STDIN) {
            childfd[0] = xopen("/dev/null", O_RDONLY, 0);
            parentfd[0] = xopen("/dev/null", O_WRONLY, 0);
        } else {
            xpipe(&childfd[0], &parentfd[0]);
        }

        if (flags & CHILD_PTY_STDOUT) {
            childfd[1] = xdup(pty_slave);
            parentfd[1] = xdup(pty_master);
        } else if (flags & CHILD_NULL_STDOUT) {
            childfd[1] = xopen("/dev/null", O_WRONLY, 0);
            parentfd[1] = xopen("/dev/null", O_RDONLY, 0);
        } else {
            xpipe(&parentfd[1], &childfd[1]);
        }
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
    } else if (flags & CHILD_NULL_STDERR) {
        childfd[2] = xopen("/dev/null", O_WRONLY, 0);
        parentfd[2] = xopen("/dev/null", O_RDONLY, 0);
    } else {
        xpipe(&parentfd[2], &childfd[2]);
    }

    WITH_CURRENT_RESLIST(rl->parent);

    child->flags = flags;
    child->deathsig = csi->deathsig;
    if (pty_master != -1)
        child->pty_master = fdh_dup(pty_master);
    child->fd[0] = fdh_dup(parentfd[0]);
    child->fd[1] = fdh_dup(parentfd[1]);
    if ((flags & CHILD_INHERIT_STDERR) == 0)
        child->fd[2] = fdh_dup(parentfd[2]);

    // We need to block all signals until the child calls signal(2) to
    // reset its signal handlers to the default.  If we didn't, the
    // child could run handlers we didn't expect.

    sigset_t all_blocked;
    sigset_t prev_blocked;

    VERIFY(sigfillset(&all_blocked) == 0);
    VERIFY(sigprocmask(SIG_SETMASK, &all_blocked, &prev_blocked) == 0);

    pid_t child_pid = fork();
    if (child_pid == 0) {
        struct internal_child_info ci = {
            .flags = flags,
            .csi = csi,
            .pty_slave = pty_slave,
            .childfd = childfd,
        };

        child_child(&ci); // Never returns
    }

    VERIFY(sigprocmask(SIG_SETMASK, &prev_blocked, NULL) == 0);
    if (child_pid == -1)
        die_errno("fork");

    child->pid = child_pid;
    cleanup_commit(cl_waiter, child_cleanup, child);
    return child;
}

int
child_wait(struct child* child)
{
    int ret;

    // N.B. THE COMMENTED CODE BELOW IS WRONG.
    //
    // do {
    //     WITH_IO_SIGNALS_ALLOWED();
    //     ret = waitpid(child->pid, &child->status, 0);
    // } while (ret < 0 && errno == EINTR);
    //
    // It looks correct, doesn't it?
    //
    // Consider what happens if we get a fatal signal, say SIGINT,
    // immediately after a successful return from waitpid() and
    // before we restore the signal mask that blocks SIGINT.
    // SIGINT runs the global cleanup handlers, one of which calls
    // kill() on our subprocess's PID.  (Normally, the assignment
    // to child->dead below prevents our calling kill().)  When
    // waitpid() completes successfully, the kernel frees the
    // process table entry for the process waited on.  Between the
    // waitpid() return and our call to kill(), another process
    // can move into that process table slot, resulting in our
    // subsequent kill() going to wrong process and killing an
    // innocent program.
    //
    // Instead, we first block SIGCHLD (in addition to signals
    // like SIGINT), then, _WITHOUT_ unblocking signals, call
    // waitpid(..., WNOHANG).  If that succeeds, our child is dead
    // and we remember its status.  If waitpid() indicates that
    // our child is still running, we then call sigwait({SIGCHLD,
    // SIGINT}); when the child dies, we loop around and call
    // waitpid() again.  That waitpid() might fail if a different
    // child died, or if we got a non-SIGCHLD signal, but
    // eventually our child will die, waitpid() will succeed, and
    // we'll exit the loop.
    //

    sigset_t block_during_poll;

    if (!child->dead) {
        sigemptyset(&block_during_poll);
        for (int i = 1; i < NSIG; ++i)
            if (!sigismember(&signals_unblock_for_io, i))
                sigaddset(&block_during_poll, i);

        sigdelset(&block_during_poll, SIGCHLD);
    }

    while (!child->dead) {
        ret = waitpid(child->pid, &child->status, WNOHANG);
        if (ret < 0) {
            // waitpid will fail if child->pid isn't really our child;
            // that means we have a bug somewhere, since it should be
            // a zombie until we wait for it.
            die_errno("waitpid(%u)", (unsigned) child->pid);
        }

        if (ret > 0) {
            child->dead = true;
        } else {
            if (pselect(0, NULL, NULL, NULL, NULL, &block_during_poll) < 0
                && errno != EINTR)
            {
                die_errno("pselect");
            }
        }
    }

    return child->status;
}

void
child_kill(struct child* child, int signo)
{
    if (!child->dead && kill(child->pid, signo) == -1)
        die_errno("kill");
}

static bool
any_poll_active_p(const struct pollfd* p, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        if (p[i].fd != -1)
            return true;

    return false;
}

struct child_communication*
child_communicate(
    struct child* child,
    const void* data_for_child_in,
    size_t data_for_child_size)
{
    const uint8_t* data_for_child = data_for_child_in;
    size_t bytes_consumed = 0;
    size_t chunk_size = 512;

    struct pollfd p[ARRAYSIZE(child->fd)];
    memset(&p, 0, sizeof (p));

    struct {
        struct cleanup* cl;
        uint8_t* buf;
        size_t pos;
        size_t sz;
    } ob[ARRAYSIZE(child->fd)-1];

    memset(&ob, 0, sizeof (ob));

    for (int i = 0; i < ARRAYSIZE(p); ++i) {
        int fd = child->fd[i]->fd;
        fd_set_blocking_mode(fd, non_blocking);
        p[i].fd = fd;
        p[i].events = (i == 0) ? POLLIN : POLLOUT;
    }

    for (;;) {
        if (p[0].fd != -1) {
            size_t nr_to_write = data_for_child_size - bytes_consumed;
            if (nr_to_write > 0) {
                ssize_t nr_written =
                    write(p[0].fd,
                          data_for_child + bytes_consumed,
                          XMIN(nr_to_write, (size_t) SSIZE_MAX));

                if (nr_written == -1 && !error_temporary_p(errno))
                    die_errno("write[child]");

                bytes_consumed += XMAX(nr_written, 0);
            }

            if (bytes_consumed == data_for_child_size) {
                fdh_destroy(child->fd[0]);
                p[0].fd = -1;
            }
        }

        for (size_t i = 0; i < ARRAYSIZE(ob); ++i) {
            int fd = p[i+1].fd;
            if (fd == -1)
                continue;

            if (ob[i].pos == ob[i].sz) {
                struct cleanup* newcl = cleanup_allocate();
                size_t newsz;
                if (SATADD(&newsz, ob[i].sz, chunk_size))
                    die(ERANGE, "too many bytes from child");

                void* newbuf = realloc(ob[i].buf, newsz);
                if (newbuf == NULL)
                    die(ENOMEM, "could not allocate iobuf");

                cleanup_commit(newcl, free, newbuf);
                cleanup_forget(ob[i].cl);
                ob[i].cl = newcl;
                ob[i].buf = newbuf;
                ob[i].sz = newsz;
            }

            size_t to_read = ob[i].sz - ob[i].pos;
            ssize_t nr_read = read(fd, ob[i].buf + ob[i].pos, to_read);
            if (nr_read == -1 && !error_temporary_p(errno))
                die_errno("read[child:%d]", fd);

            ob[i].pos += XMAX(0, nr_read);
            if (nr_read == 0) {
                fdh_destroy(child->fd[i+1]);
                p[i+1].fd = -1;
            }
        }

        if (!any_poll_active_p(p, ARRAYSIZE(p)))
            break;

        int rc;

        {
            WITH_IO_SIGNALS_ALLOWED();
            rc = ppoll(p, ARRAYSIZE(p), NULL, NULL);
        }

        if (rc == -1 && errno != EINTR)
            die_errno("ppoll");
    }

    struct child_communication* com = xcalloc(sizeof (*com));
    com->status = child_wait(child);
    com->bytes_consumed = bytes_consumed;
    for (size_t i = 0; i < ARRAYSIZE(ob); ++i) {
        com->out[i].bytes = ob[i].buf;
        com->out[i].nr = ob[i].pos;
    }

    return com;
}

bool
child_status_success_p(int status)
{
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
