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
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <sys/time.h>
#include <stdlib.h>
#include "channel.h"
#include "util.h"
#include "ringbuf.h"
#include "adbenc.h"
#include "xmkraw.h"
#include "fs.h"

static bool
channel_nonblock_hack_p(struct channel* c)
{
#ifdef FBADB_CHANNEL_NONBLOCK_HACK
    return c->nonblock_hack;
#else
    return false;
#endif
}

struct channel*
channel_new(struct fdh* fdh,
            size_t rbsz,
            enum channel_direction direction)
{
    struct channel* ch = xcalloc(sizeof (*ch));
    ch->fdh = fdh;
    ch->dir = direction;
    ch->rb = ringbuf_new(rbsz);
    return ch;
}

static size_t
channel_wanted_readsz(struct channel* c)
{
    if (c->dir != CHANNEL_FROM_FD)
        return 0;

    if (c->fdh == NULL)
        return 0;

    return XMIN(ringbuf_room(c->rb), c->window);
}

static size_t
channel_wanted_writesz(struct channel* c)
{
    if (c->dir != CHANNEL_TO_FD)
        return 0;

    if (c->fdh == NULL)
        return 0;

    // If c->adb_hack_state is non-zero, we need to write the second
    // half of an adb-escaped character pair.
    return XMIN(ringbuf_size(c->rb), UINT32_MAX - c->bytes_written)
        + !!(c->adb_hack_state);
}

static size_t
channel_read_1(struct channel* c, size_t sz)
{
    size_t nr_read = ringbuf_read_in(c->rb, c->fdh->fd, sz);
    ringbuf_note_added(c->rb, nr_read);
    return nr_read;
}

static size_t
channel_write_1(struct channel* c, size_t sz)
{
    size_t nr_written = ringbuf_write_out(c->rb, c->fdh->fd, sz);
    ringbuf_note_removed(c->rb, nr_written);
    return nr_written;
}

static size_t
channel_read_adb_hack(struct channel* c, size_t sz)
{
    size_t nr_added = 0;

    while (nr_added < sz) {
        char buf[4096];
        size_t to_read = XMIN(sz - nr_added, sizeof (buf));
        ssize_t chunksz;

        {
            WITH_IO_SIGNALS_ALLOWED();
            chunksz = read(c->fdh->fd, buf, to_read);
        }

        if (chunksz < 0 && nr_added == 0)
            die_errno("read");
        if (chunksz < 1)
            break;

        struct iovec iov[2];
        ringbuf_writable_iov(c->rb, iov, chunksz);
        const char* in = buf;
        const char* inend = in + chunksz;
        size_t np = 0;
        for (int i = 0; i < ARRAYSIZE(iov); ++i) {
            char* decstart = iov[i].iov_base;
            char* dec = decstart;
            char* decend = dec + iov[i].iov_len;
            adb_decode(&c->adb_hack_state, &dec, decend, &in, inend);
            np += (dec - decstart);
        }

        ringbuf_note_added(c->rb, np);
        nr_added += np;
    }

    return nr_added;
}

static size_t
channel_write_adb_hack(struct channel* c, size_t sz)
{
    assert(sz > 0);
    if (c->adb_hack_state)
        sz -= 1;

    size_t nr_removed = 0;
    do {
        struct iovec iov[2];
        char encbuf[4096];
        char* enc;
        char* encend;

        ringbuf_readable_iov(c->rb, iov, sz - nr_removed);
        uint8_t pass1_state = c->adb_hack_state;

        enc = encbuf;
        encend = enc + sizeof (encbuf);
        for (int i = 0; i < ARRAYSIZE(iov); ++i) {
            const char* in = iov[i].iov_base;
            const char* inend = in + iov[i].iov_len;
            adb_encode(&pass1_state, &enc, encend, &in, inend);
        }

        size_t nr_encoded = enc - encbuf;
        ssize_t nr_written;
        {
            WITH_IO_SIGNALS_ALLOWED();
            nr_written = write(c->fdh->fd, encbuf, nr_encoded);
        }

        if (nr_written < 0 && nr_removed == 0)
            die_errno("write");
        if (nr_written < 0) {
            // write didn't actually write anything, so don't write
            // pass1_state back into c.
            break;
        }

        // We wrote nr_written _encoded_ bytes, which may be less than
        // the number of bytes we wanted to write post-encoding;
        // the latter number is nr_encoded.  Re-run the encoder
        // pretending we have only nr_written bytes available for
        // encoding --- this way, next time, we'll resume exactly
        // where we left off.

        assert(nr_written <= sizeof (encbuf));
        enc = encbuf;
        encend = enc + nr_written;
        size_t plaintext_consumed = 0;
        for (int i = 0; i < ARRAYSIZE(iov); ++i) {
            const char* in_start = iov[i].iov_base;
            const char* in = in_start;
            const char* inend = in + iov[i].iov_len;
            adb_encode(&c->adb_hack_state, &enc, encend, &in, inend);
            plaintext_consumed += (in - in_start);
        }
        ringbuf_note_removed(c->rb, plaintext_consumed);
        nr_removed += plaintext_consumed;
    } while (nr_removed < sz);

    return nr_removed;
}

struct pollfd
channel_request_poll(struct channel* c)
{
    if (channel_wanted_readsz(c))
        return (struct pollfd){c->fdh->fd, POLLIN, 0};

    if (channel_wanted_writesz(c))
        return (struct pollfd){c->fdh->fd, POLLOUT, 0};

    return (struct pollfd){-1, 0, 0};
}

void
channel_write(struct channel* c, const struct iovec* iov, unsigned nio)
{
    assert(c->dir == CHANNEL_TO_FD);

    if (c->fdh == NULL)
        return; // If the stream is closed, just discard

    bool try_direct = !c->always_buffer && ringbuf_size(c->rb) == 0;
    size_t directwrsz = 0;
    size_t totalsz;

    if (c->adb_encoding_hack)
        try_direct = false;

    // If writing directly, would make us overflow the write counter,
    // fall back to buffered IO.
    if (try_direct) {
        totalsz = iovec_sum(iov, nio);
        if (c->track_bytes_written &&
            UINT32_MAX - c->bytes_written < totalsz)
        {
            try_direct = false;
        }
    }

    if (try_direct) {
        // If writev fails, just fall back to buffering path
        ssize_t res = writev(c->fdh->fd, iov, nio);
        dbg("direct write dst:%p sz:%u result:%d %s",
            c, (unsigned) totalsz, (int) res,
            res == -1 ? strerror(errno) : "");
        directwrsz = XMAX(res, 0);
        if (c->track_bytes_written)
            c->bytes_written += directwrsz;
    }

    for (unsigned i = 0; i < nio; ++i) {
        size_t skip = XMIN(iov[i].iov_len, directwrsz);
        directwrsz -= skip;
        char* b = (char*)iov[i].iov_base + skip;
        size_t blen = iov[i].iov_len - skip;
        ringbuf_copy_in(c->rb, b, blen);
        ringbuf_note_added(c->rb, blen);
    }
}

// Begin channel shutdown process.  Closure is not complete until
// channel_dead_p(c) returns true.
void
channel_close(struct channel* c)
{
    c->pending_close = true;
    if (c->fdh != NULL
        && ((c->dir == CHANNEL_TO_FD && ringbuf_size(c->rb) == 0)
            || c->dir == CHANNEL_FROM_FD))
    {
        if (c->saved_term_state) {
            unsigned ttysave_flags = (c->dir == CHANNEL_TO_FD)
                ? RAW_OUTPUT
                : RAW_INPUT;
            ttysave_restore(c->saved_term_state,
                            c->fdh->fd,
                            ttysave_flags);
            c->saved_term_state = NULL;
        }

        fdh_destroy(c->fdh);
        c->fdh = NULL;
    }
}

static void
poll_channel_2(void* arg)
{
    struct channel* c = arg;
    size_t sz;

    if ((sz = channel_wanted_readsz(c)) > 0) {
        size_t nr_read;
        if (c->adb_encoding_hack)
            nr_read = channel_read_adb_hack(c, sz);
        else
            nr_read = channel_read_1(c, sz);

        assert(nr_read <= c->window);
        if (c->track_window)
            c->window -= nr_read;

        if (nr_read == 0)
            channel_close(c);
    }

    if ((sz = channel_wanted_writesz(c)) > 0) {
        size_t nr_written;
        if (c->adb_encoding_hack)
            nr_written = channel_write_adb_hack(c, sz);
        else
            nr_written = channel_write_1(c, sz);

        assert(nr_written <= UINT32_MAX - c->bytes_written);
        if (c->track_bytes_written)
            c->bytes_written += nr_written;

        if (c->pending_close && ringbuf_size(c->rb) == 0)
            channel_close(c);
    }
}

static void
poll_channel_nonblock_hack(struct channel* c)
{
    struct itimerval nonblock_timer = {
        .it_value = {0, 10000 /* us = 10ms */},
    };

    SCOPED_RESLIST(rl);
    set_timeout(&nonblock_timer, EAGAIN, "timeout hack");
    poll_channel_2(c);
}

static void
poll_channel_1(void* arg)
{
    struct channel* c = arg;

    if (channel_nonblock_hack_p(c) && c->fdh != NULL)
        poll_channel_nonblock_hack(c);
    else
        poll_channel_2(c);
}

bool
channel_dead_p(struct channel* c)
{
    return (c->fdh == NULL &&
            ringbuf_size(c->rb) == 0 &&
            c->sent_eof == true);
}

void
channel_poll(struct channel* c)
{
    struct errinfo ei = { .want_msg = false };
    if (catch_error(poll_channel_1, c, &ei)
        && !error_temporary_p(ei.err))
    {
        if (c->dir == CHANNEL_TO_FD) {
            // Error writing to fd, so purge buffered bytes we'll
            // never write.  By purging, we also make the stream
            // appear writable (because now there's space available),
            // but any writes will actually go into a black hole.
            // This way, if somebody's blocked on being able to write
            // to this stream, he'll get unblocked.  This behavior is
            // important when c is TO_PEER and lets us complete an
            // orderly shutdown, flushing any data we've buffered,
            // without adding special logic all over the place to
            // account for this situation.
            ringbuf_note_removed(c->rb, ringbuf_size(c->rb));
        }

        channel_close(c);
        c->err = ei.err;
    }
}
