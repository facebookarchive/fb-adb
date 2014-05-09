#include <assert.h>
#include <errno.h>
#include <sys/uio.h>
#include <string.h>
#include <limits.h>
#include "ringbuf.h"
#include "util.h"

struct ringbuf {
    size_t nr_removed;
    size_t nr_added;
    size_t capacity;
    char* __restrict__ mem;
};

struct ringbuf_io {
    struct iovec v[2];
};

struct ringbuf*
ringbuf_new(size_t capacity)
{
    if (capacity == 0)
        die(ERANGE, "buffer too small");

    capacity = nextpow2sz(capacity);
    if (capacity == 0)
        die(ERANGE, "buffer too large");

    struct ringbuf* rb = xcalloc(sizeof (*rb));
    rb->capacity = capacity;
    rb->mem = xalloc(capacity);
    return rb;
}

static size_t
ringbuf_clip(const struct ringbuf* rb, size_t pos)
{
    /* rb->capacity is always a nonzero power of two */
    assert(XPOW2P(rb->capacity));
    return pos & (rb->capacity - 1);
}

size_t
ringbuf_capacity(const struct ringbuf* rb)
{
    return rb->capacity;
}

size_t
ringbuf_size(const struct ringbuf* rb)
{
    return rb->nr_added - rb->nr_removed;
}

size_t
ringbuf_room(const struct ringbuf* rb)
{
    return ringbuf_capacity(rb) - ringbuf_size(rb);
}

void
ringbuf_consume(struct ringbuf* rb, size_t nr)
{
    assert(nr <= ringbuf_size(rb));
    rb->nr_removed += nr;
}

static struct ringbuf_io
ringbuf_io_region(const struct ringbuf* rb, size_t pos, size_t len)
{
    assert(len <= rb->capacity);
    size_t idx = ringbuf_clip(rb, pos);
    struct ringbuf_io rio;
    rio.v[0].iov_base = &rb->mem[idx];
    rio.v[0].iov_len = len;
    if (idx + len > rb->capacity) {
        rio.v[0].iov_len = rb->capacity - idx;
        rio.v[1].iov_base = rb->mem;
        rio.v[1].iov_len = len - rio.v[0].iov_len;
    } else {
        rio.v[1].iov_base = NULL;
        rio.v[1].iov_len = 0;
    }

    assert(rio.v[0].iov_len + rio.v[1].iov_len == len);
    return rio;
}

size_t
ringbuf_note_added(struct ringbuf* rb, size_t nr)
{
    assert(nr <= ringbuf_room(rb));
    rb->nr_added += nr;
    return nr;
}

size_t
ringbuf_note_removed(struct ringbuf* rb, size_t nr)
{
    assert(nr <= ringbuf_size(rb));
    rb->nr_removed += nr;
    return nr;
}

size_t
ringbuf_read_in(struct ringbuf* rb, int fd, size_t sz)
{
    sz = XMIN(sz, SSIZE_MAX);
    assert(sz <= ringbuf_room(rb));
    struct ringbuf_io rio = ringbuf_io_region(rb, rb->nr_added, sz);
    ssize_t ret = readv(fd, rio.v, ARRAYSIZE(rio.v));
    if (ret < 0)
        die_errno("readv");

    return (size_t) ret;
}

void
ringbuf_copy_in(struct ringbuf* rb, const void* buf, size_t sz)
{
    assert(sz <= ringbuf_room(rb));
    struct ringbuf_io rio = ringbuf_io_region(rb, rb->nr_added, sz);
    memcpy(rio.v[0].iov_base, buf, rio.v[0].iov_len);
    buf = (char*) buf + rio.v[0].iov_len;
    memcpy(rio.v[1].iov_base, buf, rio.v[1].iov_len);
}

size_t
ringbuf_write_out(const struct ringbuf* rb, int fd, size_t sz)
{
    sz = XMIN(sz, SSIZE_MAX);
    assert(sz <= ringbuf_size(rb));
    struct ringbuf_io rio = ringbuf_io_region(rb, rb->nr_removed, sz);
    ssize_t ret = writev(fd, rio.v, ARRAYSIZE(rio.v));
    if (ret < 0)
        die_errno("writev");

    return (size_t) ret;
}

void
ringbuf_copy_out(const struct ringbuf* rb, void* buf, size_t sz)
{
    assert(sz <= ringbuf_size(rb));
    struct ringbuf_io rio = ringbuf_io_region(rb, rb->nr_removed, sz);
    memcpy(buf, rio.v[0].iov_base, rio.v[0].iov_len);
    buf = (char*) buf + rio.v[0].iov_len;
    memcpy(buf, rio.v[1].iov_base, rio.v[1].iov_len);
}

void
ringbuf_readable_iov(const struct ringbuf* rb,
                     struct iovec iov[2],
                     size_t sz)
{
    assert(sz <= ringbuf_size(rb));
    struct ringbuf_io rio = ringbuf_io_region(rb, rb->nr_removed, sz);
    iov[0] = rio.v[0];
    iov[1] = rio.v[1];
}
