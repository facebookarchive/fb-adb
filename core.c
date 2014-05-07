#include <errno.h>
#include <assert.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include "core.h"
#include "ringbuf.h"
#include "channel.h"

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
    size_t avail = ringbuf_size(rb);
    if (avail < sizeof (*mhdr))
        return false;

    ringbuf_copy_out(rb, mhdr, sizeof (*mhdr));
    return mhdr->size <= avail;
}

static void
adbx_sh_process_msg_channel_data(struct adbx_sh* sh,
                                 struct msg_channel_data* m)
{
    unsigned nrch = sh->nrch;
    struct channel* cmdch = sh->ch[FROM_PEER];

    if (m->channel <= NR_SPECIAL_CH || m->channel > nrch)
            die_proto_error("invalid channel %d", m->channel);

    struct channel* c = sh->ch[m->channel];
    if (c->dir == CHANNEL_FROM_FD)
        die_proto_error("wrong channel direction ch=%u", m->channel);

    if (c->fdh == NULL)
        return;         /* Channel already closed */

    size_t payloadsz = m->msg.size - sizeof (m);

    /* If we received more data than will fit in the receive
     * buffer, peer didn't respect window requirements.  */
    if (ringbuf_room(c->rb) < payloadsz)
        die_proto_error("window desync");

    struct iovec iov[2];
    ringbuf_iov(cmdch->rb, iov, payloadsz);
    channel_write(c, iov, 2);
    ringbuf_note_removed(cmdch->rb, payloadsz);
}

static void
adbx_sh_process_msg_channel_window(struct adbx_sh* sh,
                                   struct msg_channel_window* m)
{
    unsigned nrch = sh->nrch;

    if (m->channel <= NR_SPECIAL_CH || m->channel > nrch)
        die_proto_error("invalid channel %d", m->channel);

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
adbx_sh_process_msg_channel_close(struct adbx_sh* sh,
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
read_cmdmsg(struct adbx_sh* sh, struct msg mhdr, void* mbuf, size_t msz)
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
adbx_sh_process_msg(struct adbx_sh* sh, struct msg mhdr)
{
    struct channel* cmdch = sh->ch[FROM_PEER];

    if (mhdr.type == MSG_CHANNEL_DATA) {
        struct msg_channel_data m;
        if (mhdr.size < sizeof (m))
            die_proto_error("wrong msg size %u", mhdr.size);

        ringbuf_copy_out(cmdch->rb, &m, sizeof (m));
        ringbuf_note_removed(cmdch->rb, sizeof (m));
        adbx_sh_process_msg_channel_data(sh, &m);
    } else if (mhdr.type == MSG_CHANNEL_WINDOW) {
        struct msg_channel_window m;
        read_cmdmsg(sh, mhdr, &m, sizeof (m));
        adbx_sh_process_msg_channel_window(sh, &m);
    } else if (mhdr.type == MSG_CHANNEL_CLOSE) {
        struct msg_channel_close m;
        read_cmdmsg(sh, mhdr, &m, sizeof (m));
        adbx_sh_process_msg_channel_close(sh, &m);
    } else {
        ringbuf_note_removed(cmdch->rb, mhdr.size);
        die(ECOMM, "unrecognized command %d (sz=%hu)",
            mhdr.type, mhdr.size);
    }
}

static size_t
adbx_maxoutmsg(struct adbx_sh* sh)
{
    return XMIN(sh->max_outgoing_msg,
                ringbuf_room(sh->ch[TO_PEER]->rb));
}

static void
xmit_acks(struct channel* c, unsigned chno, struct adbx_sh* sh)
{
    size_t maxoutmsg = adbx_maxoutmsg(sh);
    struct msg_channel_window m;

    if (c->bytes_written > 0 && maxoutmsg >= sizeof (m)) {
        memset(&m, 0, sizeof (m));
        m.msg.type = MSG_CHANNEL_WINDOW;
        m.msg.size = sizeof (m);
        m.channel = chno;
        m.window_delta = c->bytes_written;
        channel_write(sh->ch[TO_PEER], &(struct iovec){&m, sizeof (m)}, 1);
        c->bytes_written = 0;
    }
}

static void
xmit_data(struct channel* c,
          unsigned chno,
          struct adbx_sh* sh)
{
    if (c->dir != CHANNEL_FROM_FD)
        return;

    size_t maxoutmsg = adbx_maxoutmsg(sh);
    size_t avail = ringbuf_size(c->rb);
    struct msg_channel_data m;

    if (maxoutmsg > sizeof (m) && avail > 0) {
        size_t payloadsz = XMIN(avail, maxoutmsg - sizeof (m));
        dbg("payloadsz: %lu", payloadsz);
        struct iovec iov[3] = {{ &m, sizeof (m) }};
        ringbuf_iov(c->rb, &iov[1], payloadsz);
        memset(&m, 0, sizeof (m));
        m.msg.type = MSG_CHANNEL_DATA;
        m.channel = chno;
        m.msg.size = iovec_sum(iov, ARRAYSIZE(iov));
        dbg("writing data");
        channel_write(sh->ch[TO_PEER], iov, ARRAYSIZE(iov));
        ringbuf_note_removed(c->rb, payloadsz);
    }
}

static void
xmit_eof(struct channel* c,
         unsigned chno,
         struct adbx_sh* sh)
{
    struct msg_channel_close m;

    if (c->fdh == NULL &&
        c->sent_eof == false &&
        ringbuf_size(c->rb) == 0 &&
        adbx_maxoutmsg(sh) >= sizeof (m))
    {
        memset(&m, 0, sizeof (m));
        m.msg.type = MSG_CHANNEL_CLOSE;
        m.msg.size = sizeof (m);
        m.channel = chno;
        channel_write(sh->ch[TO_PEER], &(struct iovec){&m, sizeof (m)}, 1);
        c->sent_eof = true;
    }
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

static void
dbgch(const char* label, struct adbx_sh* sh)
{
#ifndef NDEBUG
    SCOPED_RESLIST(rl_dbgch);
    struct channel** ch = sh->ch;
    unsigned nrch = sh->nrch;
    unsigned chno;

    dbglock();

    dbg("DBGCH[%s]", label);

    static const char* chnames[] = {
        "FROM_PEER",
        "TO_PEER",
        "CHILD_STDIN",
        "CHILD_STDOUT",
        "CHILD_STDERR"
    };

    for (chno = 0; chno < nrch; ++chno) {
        struct channel* c = ch[chno];
        struct pollfd p = channel_request_poll(ch[chno]);
        const char* pev;
        switch (p.events) {
            case POLLIN | POLLOUT:
                pev = "POLLIN,POLLOUT";
                break;
            case POLLIN:
                pev = "POLLIN";
                break;
            case POLLOUT:
                pev = "POLLOUT";
                break;
            case 0:
                pev = "NONE";
                break;
            default:
                pev = xaprintf("%xd", p.events);
                break;
        }

        assert(p.fd == -1 || p.fd == c->fdh->fd);

        dbg("  %-18s rb_size:%-4lu rb_room:%-4lu %s%-2s %s",
            xaprintf("ch[%d=%s]", chno, chnames[chno]),
            ringbuf_size(c->rb),
            ringbuf_room(c->rb),
            (c->dir == CHANNEL_FROM_FD ? "<" : ">"),
            ((c->fdh != NULL)
             ? xaprintf("%d", c->fdh->fd)
             : (c->sent_eof ? "!!" : "!?")),
            pev);
    }
#endif
}

void
io_loop_init(struct adbx_sh* sh)
{
    struct channel** ch = sh->ch;
    unsigned nrch = sh->nrch;
    unsigned chno;
    for (chno = 0; chno < nrch; ++chno)
        if (ch[chno]->fdh != NULL)
            fd_set_blocing_mode(ch[chno]->fdh->fd, non_blocking);
}

void
io_loop_do_io(struct adbx_sh* sh)
{
    dbgch("before io_loop_do_io", sh);

    struct channel** ch = sh->ch;
    unsigned nrch = sh->nrch;
    struct pollfd polls[nrch];
    short work = 0;
    for (unsigned chno = 0; chno < nrch; ++chno) {
        polls[chno] = channel_request_poll(ch[chno]);
        work |= polls[chno].events;
    }

    if (work != 0) {
        if (poll(polls, nrch, -1) < 0 && errno != EINTR) {
            die_errno("poll");
        }
    }

    for (unsigned chno = 0; chno < nrch; ++chno)
        if (polls[chno].revents != 0)
            channel_poll(ch[chno]);
}

void
io_loop_pump(struct adbx_sh* sh)
{
    SCOPED_RESLIST(rl_io_loop);

    struct channel** ch = sh->ch;
    unsigned chno;
    unsigned nrch = sh->nrch;
    assert(nrch >= NR_SPECIAL_CH);

    struct msg mhdr;
    while (detect_msg(ch[FROM_PEER]->rb, &mhdr)) {
        dbg("received msg %u", mhdr.type);
        sh->process_msg(sh, mhdr);
    }

    for (chno = 0; chno < nrch; ++chno)
        xmit_acks(ch[chno], chno, sh);

    for (chno = 0; chno < nrch; ++chno) {
        if (chno != TO_PEER)
            xmit_data(ch[chno], chno, sh);

        do_pending_close(ch[chno]);
        xmit_eof(ch[chno], chno, sh);
    }
}

void
queue_message_synch(struct adbx_sh* sh, struct msg* m)
{
    PUMP_WHILE(sh, adbx_maxoutmsg(sh) < m->size);
    channel_write(sh->ch[TO_PEER], &(struct iovec){m, m->size}, 1);
}
