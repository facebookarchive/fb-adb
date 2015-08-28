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
#include <termios.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "xmkraw.h"
#include "util.h"

void
xtcgetattr(int fd, struct termios* attr)
{
    int ret;

    do {
        ret = tcgetattr(fd, attr);
    } while (ret == -1 && errno == EINTR);

    if (ret < 0)
        die_errno("tcgetattr(%d)", fd);
}

void
xtcsetattr(int fd, const struct termios* attr)
{
    int ret;

    do {
        ret = tcsetattr(fd, TCSADRAIN, (struct termios*) attr);
    } while (ret == -1 && errno == EINTR);

    // POSIX allows tcsetattr to fail with EIO on SIGTTOU, but we
    // don't care about the orphaned case, since if we're orphaned,
    // the user doesn't care about us either.

    if (ret < 0 && errno != EIO)
        die_errno("tcsetattr(%d)", fd);

    if (errno == EIO)
        dbg("tcsetattr failed with EIO; ignoring");
}

struct ttysave {
    LIST_ENTRY(ttysave) link;
    unsigned refcount;
#ifdef INPUT_OUTPUT_TERMIOS
    unsigned refcount_in;
    unsigned refcount_out;
#endif
    dev_t dev;
    ino_t ino;
    bool suspended;
    struct termios saved;
    struct termios desired;
};

static LIST_HEAD(,ttysave) tty_head =
    LIST_HEAD_INITIALIZER(ttysave_head);

static void
ttysave_check(struct ttysave* tty, int fd)
{
#ifndef NDEBUG
    struct stat st;
    if (fstat(fd, &st) == -1) die_errno("fstat");
    assert(st.st_dev == tty->dev);
    assert(st.st_ino == tty->ino);
#endif
}

static void
ttysave_update(struct ttysave* tty, int fd)
{
    struct termios raw = tty->saved;

#ifdef INPUT_OUTPUT_TERMIOS
    if (tty->refcount_in > 0 &&
        tty->refcount_out > 0)
    {
        cfmakeraw(&raw);
    } else if (tty->refcount_in > 0) {
        raw.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
        raw.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
        raw.c_cflag &= ~(CSIZE|PARENB);
        raw.c_cflag |= CS8;
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;
    } else if (tty->refcount_out > 0) {
        raw.c_oflag &= ~OPOST;
        raw.c_cflag &= ~(CSIZE|PARENB);
        raw.c_cflag |= CS8;
    }
#else
    if (tty->refcount > 0)
        cfmakeraw(&raw);
#endif

    if (memcmp(&raw, &tty->desired, sizeof (struct termios)) != 0) {
        memcpy(&tty->desired, &raw, sizeof (struct termios));
        xtcsetattr(fd, &tty->desired);
    }
}

void
ttysave_before_suspend(struct ttysave* tty, int fd)
{
    ttysave_check(tty, fd);
    if (!tty->suspended) {
        dbg("ttysave_before_suspend for %u/%u (fd:%u)",
            (unsigned) tty->dev,
            (unsigned) tty->ino,
            fd);
        xtcsetattr(fd, &tty->saved);
        tty->suspended = true;
    }
}

void
ttysave_after_resume(struct ttysave* tty, int fd)
{
    ttysave_check(tty, fd);
    if (tty->suspended) {
        dbg("ttysave_after_resume for %u/%u (fd:%u)",
            (unsigned) tty->dev,
            (unsigned) tty->ino,
            fd);
        xtcsetattr(fd, &tty->desired);
        tty->suspended = false;
    }
}

void
ttysave_after_sigcont(struct ttysave* tty, int fd)
{
    ttysave_check(tty, fd);
    dbg("ttysave_after_sigcont for %u/%u (fd:%u)",
        (unsigned) tty->dev,
        (unsigned) tty->ino,
        fd);
    xtcsetattr(fd, &tty->desired);
    tty->suspended = false;
}

void
ttysave_restore(struct ttysave* tty, int fd, unsigned flags)
{
    assert(!tty->suspended);
    ttysave_check(tty, fd);
    dbg("ttysave_restore for %u/%u (fd:%u) rc:%u->%u",
        (unsigned) tty->dev,
        (unsigned) tty->ino,
        fd,
        tty->refcount,
        tty->refcount-1);

#ifdef INPUT_OUTPUT_TERMIOS
    if (flags & RAW_INPUT) {
        assert(tty->refcount_in > 0);
        tty->refcount_in -= 1;
    }

    if (flags & RAW_OUTPUT) {
        assert(tty->refcount_out > 0);
        tty->refcount_out -= 1;
    }
#endif

    tty->refcount -= 1;
    ttysave_update(tty, fd);
    if (tty->refcount == 0) {
        xtcsetattr(fd, &tty->saved);
        LIST_REMOVE(tty, link);
        free(tty);
    }
}

struct ttysave*
ttysave_make_raw(int fd, unsigned flags)
{
    SCOPED_RESLIST(rl);
    struct ttysave* tty;
    struct stat st;
    struct cleanup* cl = NULL;
    if (fstat(fd, &st) == -1)
        die_errno("fstat");

    LIST_FOREACH(tty, &tty_head, link) {
        if (tty->dev == st.st_dev &&
            tty->ino == st.st_ino)
        {
            dbg("ttysave for %u/%u found (fd:%u) rc:%u->%u",
                (unsigned) tty->dev,
                (unsigned) tty->ino,
                fd,
                tty->refcount,
                tty->refcount+1);
            goto have_tty;
        }
    }

    cl = cleanup_allocate();
    tty = calloc(1, sizeof (*tty));
    if (tty == NULL)
        die_oom();
    cleanup_commit(cl, free, tty);

    tty->dev = st.st_dev;
    tty->ino = st.st_ino;
    xtcgetattr(fd, &tty->saved);
    memcpy(&tty->desired, &tty->saved, sizeof (struct termios));

    dbg("made new ttysave for %u/%u (fd:%u)",
        (unsigned) tty->dev,
        (unsigned) tty->ino,
        fd);

    have_tty:

    tty->refcount += 1;

#ifdef INPUT_OUTPUT_TERMIOS
    if (flags & RAW_INPUT)
        tty->refcount_in += 1;
    if (flags & RAW_OUTPUT)
        tty->refcount_out += 1;
#endif

    ttysave_update(tty, fd);
    cleanup_forget(cl);
    LIST_INSERT_HEAD(&tty_head, tty, link);
    return tty;
}
