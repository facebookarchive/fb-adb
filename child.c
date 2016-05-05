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
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <assert.h>
#include <limits.h>
#include "child.h"
#include "net.h"
#include "fs.h"
#include "fdrecorder.h"
#include "constants.h"
#include "argv.h"

struct internal_child_info {
    int flags;
    const struct child_start_info* csi;
    int* childfd;
    int pty_slave;
    sigset_t signals_to_ignore;
    sigset_t signals_to_block;
};

__attribute__((noreturn))
static void
child_child_1(void* arg)
{
    struct internal_child_info* ci = arg;

    memcpy(&orig_sigmask, &ci->signals_to_block, sizeof (sigset_t));
    memcpy(&orig_sig_ignored, &ci->signals_to_ignore, sizeof (sigset_t));

    /* Resets O_CLOEXEC */
    for (int i = 0; i < 3; ++i)
        xdup3nc(ci->childfd[i], i, 0);

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

    if (ci->csi->pre_exec)
        ci->csi->pre_exec(ci->csi->pre_exec_data);

    xexecvpe(ci->csi->exename,
             ci->csi->argv,
             ci->csi->environ ?: (const char* const*) environ);
}

static void
child_child_print_error(void* data)
{
    struct errinfo* ei = data;
    xprintf(xstderr, "%s: %s\n", ei->prgname, ei->msg);
    xflush(xstderr);
}

__attribute__((noreturn))
static void
child_child(struct internal_child_info* ci)
{
    struct errinfo ei = { 0 };
    ei.want_msg = true;
    if (!catch_error(child_child_1, ci, &ei)) {
        // child_child_1 should not have returned successfully
        abort();
    }

    (void) catch_error(child_child_print_error, &ei, NULL);
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

            (void) kill(child_pid, sig);
        } else {
            /* In the pty case, the system's automatic SIGHUP should
             * take care of the killing.  */
            fdh_destroy(child->pty_master);
        }

        if (!child->skip_cleanup_wait && !signal_quit_in_progress)
            child_wait(child);
    }
}

static void
swapfd(int* a, int* b)
{
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

static int
dummy_parent_fd(int for_fdno)
{
    return for_fdno == 0
        ? xopen("/dev/null", O_WRONLY, 0)
        : xopen("/dev/null", O_RDONLY, 0);
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

    for (unsigned i = 0; i < 3; ++i)
        if (csi->io[i] == CHILD_IO_PTY)
            flags |= (CHILD_CTTY | CHILD_SETSID);

    if (flags & CHILD_CTTY)
        flags |= CHILD_SETSID;

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

#ifndef NDEBUG
    for (unsigned i = 0; i < 3; ++i)
        parentfd[i] = childfd[i] = -1;
#endif

    for (unsigned i = 0; i < 3; ++i) {
        enum child_io_mode io_mode = csi->io[i];
        // If we want a pty for both of the child's standard streams,
        // make sure that we attempt to read output from only one of
        // those streams, otherwise the child will appear from the
        // parent's point of view to randomly interleave writes to
        // standard output and standard error depending on the order
        // in which we poll the parent-side FDs.
        if (i == 2 && io_mode == CHILD_IO_PTY && csi->io[1] == CHILD_IO_PTY)
            io_mode = CHILD_IO_DUP_TO_STDOUT;

        switch (io_mode) {
            case CHILD_IO_DEV_NULL:
                childfd[i] = xopen("/dev/null", O_WRONLY, 0);
                parentfd[i] = xopen("/dev/null", O_RDONLY, 0);
                if (i == 0) swapfd(&childfd[i], &parentfd[i]);
                break;
            case CHILD_IO_PTY:
                childfd[i] = xdup(pty_slave);
                parentfd[i] = xdup(pty_master);
                break;
            case CHILD_IO_PIPE:
                xpipe(&parentfd[i], &childfd[i]);
                if (i == 0) swapfd(&childfd[i], &parentfd[i]);
                break;
            case CHILD_IO_INHERIT:
                childfd[i] = xdup(i);
                parentfd[i] = dummy_parent_fd(i);
                break;
            case CHILD_IO_RECORD: {
                if (i == 0) die(EINVAL, "cannot record stdin");
                WITH_CURRENT_RESLIST(rl->parent);
                child->recorder[i] = fdrecorder_new();
                childfd[i] = fdrecorder_write_fd(child->recorder[i]);
                parentfd[i] = dummy_parent_fd(i);
                break;
            }
            case CHILD_IO_DUP_TO_STDOUT:
                if (i != 2) die(EINVAL, "can dup only stderr to stdout");
                childfd[i] = xdup(childfd[1]);
                parentfd[i] = dummy_parent_fd(i);
                break;
        }
    }

    WITH_CURRENT_RESLIST(rl->parent);

    child->flags = flags;
    child->deathsig = csi->deathsig;
    if (pty_master != -1)
        child->pty_master = fdh_dup(pty_master);
    child->fd[0] = fdh_dup(parentfd[0]);
    child->fd[1] = fdh_dup(parentfd[1]);
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

        if ((flags & CHILD_SETSID)) {
            // If we own the child's session, we own its signal
            // disposition too, so don't let inherit anything
            // about signals.
            sigemptyset(&ci.signals_to_ignore);
            sigemptyset(&ci.signals_to_block);
        } else {
            memcpy(&ci.signals_to_ignore,
                   &orig_sig_ignored,
                   sizeof (sigset_t));
            memcpy(&ci.signals_to_block,
                   &orig_sigmask,
                   sizeof (sigset_t));
        }

        child_child(&ci); // Never returns
    }

    VERIFY(sigprocmask(SIG_SETMASK, &prev_blocked, NULL) == 0);
    if (child_pid == -1)
        die_errno("fork");

    child->pid = child_pid;
    cleanup_commit(cl_waiter, child_cleanup, child);

    for (unsigned i = 0; i < 3; ++i)
        if (child->recorder[i] != NULL)
            fdrecorder_close_write_fd(child->recorder[i]);

    return child;
}

bool
child_poll_death(struct child* child)
{
    if (!child->dead) {
        int ret = waitpid(child->pid, &child->status, WNOHANG);
        if (ret < 0)
            die_errno("waitpid");

        if (ret > 0)
            child->dead = true;
    }

    return child->dead;
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
    // Instead, we first block SIGCHLD (in addition to signals like
    // SIGINT), then, _WITHOUT_ unblocking signals, call waitpid(...,
    // WNOHANG).  If that succeeds, our child is dead and we remember
    // its status.  If waitpid() indicates that our child is still
    // running, we then wait for signals; when the child dies, we loop
    // around and call waitpid() again.  That waitpid() might fail if
    // a different child died, or if we got a non-SIGCHLD signal, but
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
            sigsuspend(&block_during_poll);
        }
    }

    return child->status;
}

void
child_wait_die_on_error(struct child* c)
{
    int status = child_wait(c);
    if (!child_status_success_p(status)) {
        if (WIFEXITED(status))
            die(ECOMM,
                "child died with status %d",
                (int) WEXITSTATUS(status));
        if (WIFSIGNALED(status))
            die(ECOMM,
                "child died with signal %d",
                (int) WTERMSIG(status));
        abort();
    }
}

void
child_kill(struct child* child, int signo)
{
    if (!child->dead && kill(child->pid, signo) == -1)
        die_errno("kill");
}

bool
child_status_success_p(int status)
{
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int
child_status_to_exit_code(int status)
{
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    abort();
}

char*
massage_output(const void* buf, size_t nr_bytes)
{
    SCOPED_RESLIST(rl);
    char* output = xstrndup(buf, nr_bytes);
    char* saveptr = NULL;
    char* line;

    const char* prefixes[] = {
        xaprintf("%s: ", prgname),
        "error: ",
        NULL
    };

    for (line = strtok_r(output, "\r\n", &saveptr);
         line != NULL;
         line = strtok_r(NULL, "\r\n", &saveptr))
    {
        if (string_starts_with_p(line, "WARNING: linker: "))
            continue;
        bool changed;
        do {
            changed = false;
            const char** pp = prefixes;
            const char* prefix;
            while (!changed && (prefix = *pp++)) {
                if (strncmp(line, prefix, strlen(prefix)) == 0) {
                    line += strlen(prefix);
                    changed = true;
                }
            }
        } while (changed);
        if (line[0] != '\0')
            break;
    }

    if (line == NULL)
        line = "";
    else
        rtrim(line, NULL, "\r\n");
    WITH_CURRENT_RESLIST(rl->parent);
    return xstrdup(line);
}

char*
massage_output_buf(struct growable_buffer errbuf)
{
    return massage_output(errbuf.buf, errbuf.bufsz);
}

static void
child_error_converter(int err, void* data)
{
    if (err == ECOMM || err == EPIPE) {
        struct child* child = data;
        assert(child->recorder[STDERR_FILENO]);
        struct growable_buffer buffer =
            fdrecorder_get_clean(child->recorder[STDERR_FILENO]);
        if (buffer.bufsz > 0)
            die(ECOMM, "%s", massage_output(buffer.buf, buffer.bufsz));
    }
}

void
install_child_error_converter(struct child* child)
{
    assert(child->recorder[STDERR_FILENO] != NULL);
    install_error_converter(child_error_converter, child);
}

int
xsystem(const char* cmd)
{
    struct child_start_info csi = {
        .exename = DEFAULT_SHELL,
        .argv = ARGV("sh", "-c", cmd),
        .io[0] = CHILD_IO_INHERIT,
        .io[1] = CHILD_IO_INHERIT,
        .io[2] = CHILD_IO_INHERIT,
    };

    return child_status_to_exit_code(child_wait(child_start(&csi)));
}
