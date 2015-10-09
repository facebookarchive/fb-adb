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
#include <string.h>
#include <stddef.h>
#include <limits.h>
#include "fdrecorder.h"
#include "util.h"
#include "fs.h"
#include "net.h"

#ifndef FDRECORDER_USE_PIPE
# ifdef HAVE_PIPE2
#  define FDRECORDER_USE_PIPE 1
# else
#  define FDRECORDER_USE_PIPE 0
# endif
#endif

__attribute__((unused))
static void
xshutdown_if_not_broken(int socket, int how)
{
#if FDRECORDER_USE_PIPE
    xshutdown(socket, how);
#endif
}

struct fdrecorder {
    struct reslist* owner_rl;
    struct growable_buffer buffer;
    size_t nr_bytes_recorded;
    struct sigio_cookie* sigio_cookie;
    int pipe[2];
};

static void
fdrecorder_close_read_fd(struct fdrecorder* fdr)
{
#if !FDRECORDER_USE_PIPE
    xshutdown_if_not_broken(fdr->pipe[0], SHUT_RD);
#endif
    xclose(fdr->pipe[0]);
    fdr->pipe[0] = -1;
    if (fdr->sigio_cookie) {
        sigio_unregister(fdr->sigio_cookie);
        fdr->sigio_cookie = NULL;
    }
}

static void
fdrecorder_poll(struct fdrecorder* fdr)
{
    if (fdr->pipe[0] == -1)
        return;

    WITH_CURRENT_RESLIST(fdr->owner_rl);
    ssize_t nr_bytes_read = 0;

    do {
        fdr->nr_bytes_recorded += nr_bytes_read;
        if (fdr->nr_bytes_recorded == fdr->buffer.bufsz)
            grow_buffer_dwim(&fdr->buffer);
        size_t available = fdr->buffer.bufsz - fdr->nr_bytes_recorded;
        if (available > SSIZE_MAX)
            available = SSIZE_MAX;
        do {
            nr_bytes_read = read(
                fdr->pipe[0],
                fdr->buffer.buf + fdr->nr_bytes_recorded,
                available);
        } while (nr_bytes_read == -1 && errno == EINTR);
    } while (nr_bytes_read > 0);

    if (nr_bytes_read == -1 && errno != EAGAIN && errno != EWOULDBLOCK)
        die_errno("read(%d)", fdr->pipe[0]);

    if (nr_bytes_read == 0)
        fdrecorder_close_read_fd(fdr);
}

static void
fdrecorder_sigio_callback(void* data)
{
    fdrecorder_poll((struct fdrecorder*) data);
}

static void
fdrecorder_cleanup(void* data)
{
    struct fdrecorder* fdr = data;
    if (fdr->sigio_cookie)
        sigio_unregister(fdr->sigio_cookie);

    for (unsigned i = 0; i < 2; ++i)
        if (fdr->pipe[i] != -1)
            xclose(fdr->pipe[i]);
}

struct fdrecorder*
fdrecorder_new(void)
{
    struct reslist* fdr_rl = reslist_create();
    WITH_CURRENT_RESLIST(fdr_rl);
    struct cleanup* fdr_cl = cleanup_allocate();
    struct fdrecorder* fdr = xcalloc(sizeof (*fdr));
    fdr->owner_rl = fdr_rl;
    fdr->pipe[0] = fdr->pipe[1] = -1;
    cleanup_commit(fdr_cl, fdrecorder_cleanup, fdr);
#if FDRECORDER_USE_PIPE
    if (pipe2(fdr->pipe, O_CLOEXEC) == -1)
        die_errno("pipe2");
#else
    xsocketpairnc(AF_UNIX, SOCK_STREAM, 0, fdr->pipe);
    xshutdown_if_not_broken(fdr->pipe[0], SHUT_WR);
    xshutdown_if_not_broken(fdr->pipe[1], SHUT_RD);
#endif
    fdr->sigio_cookie = sigio_register(fdrecorder_sigio_callback, fdr);
    xF_SETFL(fdr->pipe[0], xF_GETFL(fdr->pipe[0]) | O_ASYNC | O_NONBLOCK);
    if (fcntl(fdr->pipe[0], F_SETOWN, getpid()) == -1)
        die_errno("F_SETOWN(%d)", fdr->pipe[0]);
    return fdr;
}

int
fdrecorder_write_fd(struct fdrecorder* fdr)
{
    return fdr->pipe[1];
}

void
fdrecorder_close_write_fd(struct fdrecorder* fdr)
{
    if (fdr->pipe[1] != -1) {
        xclose(fdr->pipe[1]);
        fdr->pipe[1] = -1;
    }
}

struct growable_buffer
fdrecorder_get_clean(struct fdrecorder* fdr)
{
    fdrecorder_poll(fdr);
    struct growable_buffer buffer = fdr->buffer;
    assert(fdr->nr_bytes_recorded <= buffer.bufsz);
    resize_buffer(&buffer, fdr->nr_bytes_recorded);
    memset(&fdr->buffer, 0, sizeof (fdr->buffer));
    fdr->nr_bytes_recorded = 0;
    return buffer;
}
