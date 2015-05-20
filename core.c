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
#include <assert.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <limits.h>
#include "core.h"
#include "ringbuf.h"
#include "channel.h"
#include "constants.h"
#include "lz4.h"

// If non-zero, transfer as much data as possible between ringbuffers.
// If zero, run the event loop (and do IO) between iterations.
// Unclear which approach is better, so let's default the one that
// lets us do bigger IOs.
#ifndef BATCH_WORK_IF_POSSIBLE
#define BATCH_WORK_IF_POSSIBLE 1
#endif

#ifndef TURN_INCREMENT
#define TURN_INCREMENT 1
#endif

__attribute__((noreturn,format(printf,1,2)))
static void
die_proto_error(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    die(ECOMM,
        "protocol error: %s",
        xavprintf(fmt, args));
}

static bool
detect_msg(struct ringbuf* rb, struct msg* mhdr)
{
    memset(mhdr, 0, sizeof (*mhdr));
    size_t avail = ringbuf_size(rb);
    if (avail < sizeof (*mhdr))
        return false;

    ringbuf_copy_out(rb, mhdr, sizeof (*mhdr));
    if (avail < mhdr->size) {
        if (mhdr->size - avail > ringbuf_room(rb))
            die_proto_error("impossibly large message: "
                            "type:%u sz:%lu room:%lu",
                            mhdr->type,
                            (unsigned long)(mhdr->size - avail),
                            (unsigned long)ringbuf_room(rb));

        return false;
    }

    return true;                /* Can now read msg */
}

static void
fb_adb_sh_process_msg_channel_data(struct fb_adb_sh* sh,
                                   struct msg_channel_data* m)
{
    unsigned nrch = sh->nrch;
    struct channel* cmdch = sh->ch[FROM_PEER];

    if (m->channel <= NR_SPECIAL_CH || m->channel > nrch)
        die_proto_error("data: invalid channel %d", m->channel);

    struct channel* c = sh->ch[m->channel];
    if (c->dir == CHANNEL_FROM_FD)
        die_proto_error("wrong channel direction ch=%u", m->channel);

    size_t payloadsz = m->msg.size - sizeof (*m);

    if (c->fdh == NULL) {
        /* Channel already closed.  Just drop the write. */
        ringbuf_note_removed(cmdch->rb, payloadsz);
        return;
    }

    /* If we received more data than will fit in the receive
     * buffer, peer didn't respect window requirements.  */
    if (ringbuf_room(c->rb) < payloadsz)
        die_proto_error("window desync");

    struct iovec iov[2];
    ringbuf_readable_iov(cmdch->rb, iov, payloadsz);
    channel_write(c, iov, 2);
    ringbuf_note_removed(cmdch->rb, payloadsz);
}

static void
fb_adb_sh_process_msg_channel_data_lz4(struct fb_adb_sh* sh,
                                       struct msg_channel_data_lz4* m)
{
    unsigned nrch = sh->nrch;
    struct channel* cmdch = sh->ch[FROM_PEER];

    if (m->channel <= NR_SPECIAL_CH || m->channel > nrch)
        die_proto_error("data: invalid channel %d", m->channel);

    struct channel* c = sh->ch[m->channel];
    if (c->dir == CHANNEL_FROM_FD)
        die_proto_error("wrong channel direction ch=%u", m->channel);

    size_t compressed_size = m->msg.size - sizeof (*m);

    if (c->fdh == NULL) {
        /* Channel already closed.  Just drop the write. */
        ringbuf_note_removed(cmdch->rb, compressed_size);
        return;
    }

    size_t uncompressed_size = m->uncompressed_size;

    /* If we received more data than will fit in the receive
     * buffer, peer didn't respect window requirements.  */
    if (ringbuf_room(c->rb) < uncompressed_size)
        die_proto_error("window desync");

    struct iovec iov[2];
    ringbuf_readable_iov(cmdch->rb, iov, compressed_size);

    void* src_buffer;
    if (iov[0].iov_len >= compressed_size) {
        src_buffer = iov[0].iov_base;
    } else {
        src_buffer = alloca(compressed_size);
        ringbuf_copy_out(cmdch->rb, src_buffer, compressed_size);
    }

    void* dst_buffer = alloca(uncompressed_size);
    int ret = LZ4_decompress_safe(src_buffer,
                                  dst_buffer,
                                  compressed_size,
                                  uncompressed_size);

    if (ret == 0)
        die_proto_error("invalid compressed data");

    assert(ret == uncompressed_size);

    iov[0].iov_base = dst_buffer;
    iov[0].iov_len = uncompressed_size;
    channel_write(c, iov, 1);
    ringbuf_note_removed(cmdch->rb, compressed_size);
}

static void
fb_adb_sh_process_msg_channel_window(struct fb_adb_sh* sh,
                                     struct msg_channel_window* m)
{
    unsigned nrch = sh->nrch;
    if (m->channel <= NR_SPECIAL_CH || m->channel > nrch)
        die_proto_error("window: invalid channel %d", m->channel);

    struct channel* c = sh->ch[m->channel];
    if (c->dir == CHANNEL_TO_FD)
        die_proto_error("wrong channel direction");

    if (c->fdh == NULL)
        return;         /* Channel already closed */

    if (SATADD(&c->window, c->window, m->window_delta)) {
        die_proto_error("window overflow!?");
    }
}

static void
fb_adb_sh_process_msg_channel_close(struct fb_adb_sh* sh,
                                    struct msg_channel_close* m)
{
    unsigned nrch = sh->nrch;
    if (m->channel <= NR_SPECIAL_CH || m->channel > nrch)
        return;                 /* Ignore invalid close */

    struct channel* c = sh->ch[m->channel];
    c->sent_eof = true; /* Peer already knows we're closed. */
    channel_close(c);
}

void
read_cmdmsg(struct fb_adb_sh* sh, struct msg mhdr, void* mbuf, size_t msz)
{
    if (mhdr.size != msz)
        die_proto_error("wrong msg size type:%u expected:%u received:%u",
                        mhdr.type,
                        (unsigned) msz,
                        mhdr.size);

    struct channel* cmdch = sh->ch[FROM_PEER];
    ringbuf_copy_out(cmdch->rb, mbuf, msz);
    ringbuf_note_removed(cmdch->rb, msz);
}

void
fb_adb_sh_process_msg(struct fb_adb_sh* sh, struct msg mhdr)
{
    struct channel* cmdch = sh->ch[FROM_PEER];

    if (mhdr.type == MSG_CHANNEL_DATA) {
        struct msg_channel_data m;
        if (mhdr.size < sizeof (m))
            die_proto_error("wrong msg size %u", mhdr.size);

        ringbuf_copy_out(cmdch->rb, &m, sizeof (m));
        ringbuf_note_removed(cmdch->rb, sizeof (m));
        dbgmsg(&m.msg, "recv");
        fb_adb_sh_process_msg_channel_data(sh, &m);
    } else if (mhdr.type == MSG_CHANNEL_DATA_LZ4) {
        struct msg_channel_data_lz4 m;
        if (mhdr.size < sizeof (m))
            die_proto_error("wrong msg size %u", mhdr.size);

        ringbuf_copy_out(cmdch->rb, &m, sizeof (m));
        ringbuf_note_removed(cmdch->rb, sizeof (m));
        dbgmsg(&m.msg, "recv");
        fb_adb_sh_process_msg_channel_data_lz4(sh, &m);
    } else if (mhdr.type == MSG_CHANNEL_WINDOW) {
        struct msg_channel_window m;
        read_cmdmsg(sh, mhdr, &m, sizeof (m));
        dbgmsg(&m.msg, "recv");
        fb_adb_sh_process_msg_channel_window(sh, &m);
    } else if (mhdr.type == MSG_CHANNEL_CLOSE) {
        struct msg_channel_close m;
        read_cmdmsg(sh, mhdr, &m, sizeof (m));
        dbgmsg(&m.msg, "recv");
        fb_adb_sh_process_msg_channel_close(sh, &m);
    } else {
        ringbuf_note_removed(cmdch->rb, mhdr.size);
        die(ECOMM, "unrecognized command %d (sz=%hu)",
            mhdr.type, mhdr.size);
    }
}

static size_t
fb_adb_maxoutmsg(struct fb_adb_sh* sh)
{
    return XMIN(sh->max_outgoing_msg,
                ringbuf_room(sh->ch[TO_PEER]->rb));
}

static void
xmit_acks(struct channel* c, unsigned chno, struct fb_adb_sh* sh)
{
    size_t maxoutmsg = fb_adb_maxoutmsg(sh);
    struct msg_channel_window m;

    if (c->bytes_written > 0 && maxoutmsg >= sizeof (m)) {
        memset(&m, 0, sizeof (m));
        m.msg.type = MSG_CHANNEL_WINDOW;
        m.msg.size = sizeof (m);
        m.channel = chno;
        m.window_delta = c->bytes_written;
        dbgmsg(&m.msg, "send");
        channel_write(sh->ch[TO_PEER], &(struct iovec){&m, sizeof (m)}, 1);
        c->bytes_written = 0;
    }
}

static unsigned
xmit_data_uncompressed(struct channel* c,
                       unsigned chno,
                       struct channel* dst,
                       size_t avail,
                       size_t maxoutmsg)
{
    struct msg_channel_data m;
    if (maxoutmsg < sizeof (m))
        return 0;

    size_t payloadsz = XMIN(avail, maxoutmsg - sizeof (m));
    struct iovec iov[3] = {{ &m, sizeof (m) }};
    ringbuf_readable_iov(c->rb, &iov[1], payloadsz);
    memset(&m, 0, sizeof (m));
    m.msg.type = MSG_CHANNEL_DATA;
    m.msg.size = iovec_sum(iov, ARRAYSIZE(iov));
    m.channel = chno;
    assert(chno != 0);
    dbgmsg(&m.msg, "send");
    channel_write(dst, iov, ARRAYSIZE(iov));
    ringbuf_note_removed(c->rb, payloadsz);
    return 1;
}

static unsigned
xmit_data_lz4(struct channel* c,
              unsigned chno,
              struct channel* dst,
              size_t avail,
              size_t maxoutmsg)
{
    struct msg_channel_data_lz4 m;
    if (maxoutmsg < sizeof (m))
        return 0;

    int src_size = (int) XMIN(avail, (size_t) INT_MAX);
    src_size = XMIN(src_size, MAX_COMPRESSION_BLOCK);
    src_size = XMIN(src_size, UINT16_MAX);

    assert(maxoutmsg <= INT_MAX + sizeof (m));
    int dst_size = maxoutmsg - sizeof (m);
    dst_size = XMIN(dst_size, LZ4_compressBound(src_size));

    struct iovec iov[2];

    void* src_buffer;
    ringbuf_readable_iov(c->rb, &iov[0], src_size);
    if (src_size <= iov[0].iov_len) {
        src_buffer = iov[0].iov_base;
    } else {
        src_buffer = alloca(src_size);
        memcpy(src_buffer, iov[0].iov_base, iov[0].iov_len);
        memcpy((uint8_t*) src_buffer + iov[0].iov_len,
               iov[1].iov_base,
               iov[1].iov_len);
    }

    void* dst_buffer = alloca(dst_size);
    int consumed_size = src_size;
    int out_size = LZ4_compress_destSize(
        src_buffer,
        dst_buffer,
        &consumed_size,
        dst_size);

    if (out_size == 0) {
        dbg("compression failed");
        return xmit_data_uncompressed(c, chno, dst, avail, maxoutmsg);
    }

    assert(0 <= consumed_size && consumed_size <= src_size);
    assert(0 < out_size && out_size <= dst_size);

    // If the compressed version isn't better than the uncompressed
    // version, send the uncompressed version.
    size_t equiv_uncompressed =
        consumed_size + sizeof (struct msg_channel_data);

    if (out_size + sizeof (m) >= equiv_uncompressed) {
        return xmit_data_uncompressed(
            c, chno, dst, consumed_size, maxoutmsg);
    }

    memset(&m, 0, sizeof (m));
    m.msg.type = MSG_CHANNEL_DATA_LZ4;
    m.msg.size = out_size + sizeof (m);
    m.uncompressed_size = (unsigned) consumed_size;
    m.channel = chno;

    memset(&iov, 0, sizeof (iov));
    iov[0].iov_base = &m;
    iov[0].iov_len = sizeof (m);
    iov[1].iov_base = dst_buffer;
    iov[1].iov_len = out_size;

    dbgmsg(&m.msg, "send-compressed");
    channel_write(dst, iov, ARRAYSIZE(iov));
    ringbuf_note_removed(c->rb, consumed_size);
    return 1;
}


static unsigned
xmit_data(struct channel* c,
          unsigned chno,
          struct fb_adb_sh* sh)
{
    unsigned work_done = 0;
    if (c->dir == CHANNEL_FROM_FD) {
        size_t maxoutmsg = fb_adb_maxoutmsg(sh);
        size_t avail = ringbuf_size(c->rb);

        if (avail > 0) {
            struct channel* dst = sh->ch[TO_PEER];

            if (c->compress && avail >= MIN_COMPRESSION_BLOCK)
                work_done =
                    xmit_data_lz4(
                        c, chno, dst, avail, maxoutmsg);
            else
                work_done =
                    xmit_data_uncompressed(
                        c, chno, dst, avail, maxoutmsg);
        }
    }

    return work_done;
}

static unsigned
xmit_eof(struct channel* c,
         unsigned chno,
         struct fb_adb_sh* sh)
{
    struct msg_channel_close m;
    unsigned work_done = 0;

    if (c->fdh == NULL &&
        c->sent_eof == false &&
        ringbuf_size(c->rb) == 0 &&
        fb_adb_maxoutmsg(sh) >= sizeof (m))
    {
        memset(&m, 0, sizeof (m));
        m.msg.type = MSG_CHANNEL_CLOSE;
        m.msg.size = sizeof (m);
        m.channel = chno;
        dbgmsg(&m.msg, "send");
        channel_write(sh->ch[TO_PEER], &(struct iovec){&m, sizeof (m)}, 1);
        c->sent_eof = true;
        work_done += 1;
    }

    return work_done;
}

static void
do_pending_close(struct channel* c)
{
    if (c->dir == CHANNEL_TO_FD &&
        c->fdh != NULL &&
        ringbuf_size(c->rb) == 0 &&
        c->pending_close)
    {
        channel_close(c);
    }
}

void
io_loop_init(struct fb_adb_sh* sh)
{
    struct channel** ch = sh->ch;
    unsigned nrch = sh->nrch;
    unsigned chno;
    for (chno = 0; chno < nrch; ++chno)
        if (ch[chno]->fdh != NULL)
            fd_set_blocking_mode(ch[chno]->fdh->fd, non_blocking);
}

void
io_loop_do_io(struct fb_adb_sh* sh)
{
    SCOPED_RESLIST(rl);
    dbgch("before polling", sh->ch, sh->nrch);

    struct channel** ch = sh->ch;
    unsigned nrch = sh->nrch;
    struct pollfd polls[nrch];
    int rc;
    short work = 0;

    for (unsigned chno = 0; chno < nrch; ++chno) {
        polls[chno] = channel_request_poll(ch[chno]);
        work |= polls[chno].events;
    }

    if (work != 0) {
#if !defined(NDEBUG) && defined(HAVE_CLOCK_GETTIME)
        double start = xclock_gettime(CLOCK_REALTIME);
#endif

        if (sh->poll_sigmask) {
            rc = xppoll(polls, nrch, NULL, sh->poll_sigmask);
        } else {
            WITH_IO_SIGNALS_ALLOWED();
            rc = poll(polls, nrch, -1);
        }

        if (rc < 0 && errno != EINTR)
            die_errno("poll");

#if !defined(NDEBUG) && defined(HAVE_CLOCK_GETTIME)
        double elapsed = xclock_gettime(CLOCK_REALTIME) - start;
        if (elapsed > 0.5)
            dbg("long poll: took %g seconds", elapsed);
#endif
    }

    for (unsigned chno = 0; chno < nrch; ++chno)
        if (polls[chno].revents != 0)
            channel_poll(ch[chno]);
}

void
io_loop_pump(struct fb_adb_sh* sh)
{
    SCOPED_RESLIST(rl);

    struct channel** ch = sh->ch;
    unsigned chno;
    unsigned i;
    unsigned nrch = sh->nrch;
    assert(nrch >= NR_SPECIAL_CH);

    struct msg mhdr;
    while (detect_msg(ch[FROM_PEER]->rb, &mhdr))
        sh->process_msg(sh, mhdr);

    // If FROM_PEER's fdh is closed, it's not going to ever receive
    // more bytes, so empty its buffer and allow the closure
    // to complete.

    if (ch[FROM_PEER]->fdh == NULL
        && ringbuf_size(ch[FROM_PEER]->rb) > 0)
    {
        dbg("dropping partial msg from dead peer");
        ringbuf_note_removed(ch[FROM_PEER]->rb,
                             ringbuf_size(ch[FROM_PEER]->rb));
    }

    for (i = 0; i < nrch; ++i) {
        chno = (i + sh->turn) % nrch;
        xmit_acks(ch[chno], chno, sh);
    }

    sh->turn += TURN_INCREMENT;

    unsigned work_done;
    do {
        work_done = 0;
        for (i = 0; i < nrch; ++i) {
            chno = (i + sh->turn) % nrch;
            if (chno > NR_SPECIAL_CH)
                work_done += xmit_data(ch[chno], chno, sh);

            do_pending_close(ch[chno]);
            work_done += xmit_eof(ch[chno], chno, sh);
        }
#if BATCH_WORK_IF_POSSIBLE == 0
        work_done = 0;
#endif
        sh->turn += TURN_INCREMENT;
    } while (work_done > 0);
}

void
queue_message_synch(struct fb_adb_sh* sh, struct msg* m)
{
    PUMP_WHILE(sh, fb_adb_maxoutmsg(sh) < m->size);
    dbgmsg(m, "send[synch]");
    channel_write(sh->ch[TO_PEER], &(struct iovec){m, m->size}, 1);
}

struct msg*
read_msg(int fd, reader rdr)
{
    struct msg mhdr;
    size_t nr_read = rdr(fd, &mhdr, sizeof (mhdr));
    if (nr_read < sizeof (mhdr))
        die_proto_error("peer disconnected");

    if (mhdr.size < sizeof (mhdr))
        die_proto_error("impossible message");

    dbg("read msg header type:%u size:%u", mhdr.type, mhdr.size);

    struct msg* m = xalloc(mhdr.size);
    memcpy(m, &mhdr, sizeof (mhdr));
    char* rest = (char*) m + sizeof (mhdr);
    size_t restsz = mhdr.size - sizeof (mhdr);
    nr_read = rdr(fd, rest, restsz);
    if (nr_read < restsz)
        die_proto_error("truncated message");

    return m;
}
