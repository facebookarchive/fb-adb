#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include "channel.h"
#include "util.h"
#include "ringbuf.h"

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

        dbg("direct write: wrote %lu bytes", directwrsz);
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
        size_t nr_read = ringbuf_read_in(c->rb, c->fdh->fd, sz);
        assert(nr_read <= c->window);
        if (c->track_window)
            c->window -= nr_read;

        ringbuf_note_added(c->rb, nr_read);
        if (nr_read == 0)
            channel_close(c);
    }

    if ((sz = channel_wanted_writesz(c)) > 0) {
        size_t nr_written = ringbuf_write_out(c->rb, c->fdh->fd, sz);
        assert(nr_written <= UINT32_MAX - c->bytes_written);
        if (c->track_bytes_written)
            c->bytes_written += nr_written;

        ringbuf_note_removed(c->rb, sz);
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
