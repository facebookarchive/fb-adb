#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include "channel.h"
#include "util.h"
#include "ringbuf.h"
#include "adbenc.h"

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

    return XMIN(ringbuf_size(c->rb), UINT32_MAX - c->bytes_written);
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
        ssize_t chunksz = read(c->fdh->fd, buf, to_read);
        if (chunksz < 0 && nr_added == 0)
            die_errno("read");
        if (chunksz < 1)
            break;

        struct iovec iov[2];
        ringbuf_writable_iov(c->rb, iov, chunksz);
        unsigned state = c->leftover_escape;
        const char* in = buf;
        const char* inend = in + chunksz;
        size_t np = 0;
        for (int i = 0; i < ARRAYSIZE(iov); ++i) {
            char* decstart = iov[i].iov_base;
            char* dec = decstart;
            char* decend = dec + iov[i].iov_len;
            adb_decode(&state, &dec, decend, &in, inend);
            np += (dec - decstart);
        }

        ringbuf_note_added(c->rb, np);
        nr_added += np;
    }

    return nr_added;
}

static ssize_t
write_skip(int fd, const void* buf, size_t sz, size_t skip)
{
    assert(skip <= sz);
    buf = (const char*) buf + skip;
    sz -= skip;
    ssize_t nr_written = write(fd, buf, sz);
    if (nr_written >= 0)
        nr_written += skip;

    return nr_written;
}

static size_t
channel_write_adb_hack(struct channel* c, size_t sz)
{
    size_t nr_removed = 0;

    while (nr_removed < sz) {
        struct iovec iov[2];
        char encbuf[4096];
        char* enc;
        char* encend;
        unsigned state;

        ringbuf_readable_iov(c->rb, iov, sz - nr_removed);
        enc = encbuf;
        encend = enc + sizeof (encbuf);
        state = c->leftover_escape;
        for (int i = 0; i < ARRAYSIZE(iov); ++i) {
            const char* in = iov[i].iov_base;
            const char* inend = in + iov[i].iov_len;
            adb_encode(&state, &enc, encend, &in, inend);
        }

        // If we left a byte in the ringbuffer, don't actually write
        // its first half now (since we wrote it before), but pretend
        // we did.
        size_t skip = (c->leftover_escape != 0);
        ssize_t nr_written =
            write_skip(c->fdh->fd, encbuf, enc - encbuf, skip);

        if (nr_written < 0 && nr_removed == 0)
            die_errno("write");
        if (nr_written < 0)
            break;

        size_t nr_encoded = 0;
        enc = encbuf;
        encend = enc + nr_written;
        state = c->leftover_escape;
        for (int i = 0; i < ARRAYSIZE(iov); ++i) {
            const char* in = iov[i].iov_base;
            const char* inend = in + iov[i].iov_len;
            adb_encode(&state, &enc, encend, &in, inend);
            nr_encoded += (in - (char*) iov[i].iov_base);
        }

        // If we wrote a partial encoded byte, leave the plain byte in
        // the ringbuf so that we know this channel still needs to
        // write.
        if (state != 0) {
            assert(nr_encoded > 0);
            nr_encoded -= 1;
        }

        ringbuf_note_removed(c->rb, nr_encoded);
        nr_removed += nr_encoded;
        c->leftover_escape = state;
    }

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
        directwrsz = XMAX(writev(c->fdh->fd, iov, nio), 0);
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
        fdh_destroy(c->fdh);
        c->fdh = NULL;
    }
}

static void
poll_channel_1(void* arg)
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
    if (catch_error(poll_channel_1, c, &ei) && ei.err != EINTR) {
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

