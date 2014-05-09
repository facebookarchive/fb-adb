#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <termios.h>
#include "util.h"
#include "child.h"
#include "ringbuf.h"
#include "proto.h"
#include "core.h"
#include "channel.h"
#include "xmkraw.h"
#include "termbits.h"
#include "adbenc.h"

static void
print_usage(void)
{
    printf("%s [-u sock]: shex\n", prgname);
}

struct adbx_shex {
    struct adbx_sh sh;
    int child_exit_status;
    bool child_exited;
};

#define SHEX_LOCAL 0x1

static void
replace_with_dev_null(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0)
        die_errno("fcntl(%d, F_GETFL)", fd);
    int nfd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (nfd == -1)
        die_errno("open(\"/dev/null\")");
    if (dup3(nfd, fd, flags & O_CLOEXEC) < 0)
        die_errno("dup3");

    close(nfd);
    if (fcntl(fd, F_SETFL, flags) < 0)
        die_errno("fcntl");
}

static size_t
argv_length(char** argv)
{
    size_t len = 0;
    while (*argv++)
        len++;

    return len;
}

static char**
concat_argv(char** argv_a, char** argv_b)
{
    size_t len_a = argv_length(argv_a);
    size_t len_b = argv_length(argv_b);
    size_t len_total;

    if (SATADD(&len_total, len_a, len_b) ||
        SATADD(&len_total, len_total, 1) ||
        (SIZE_MAX / sizeof (char*)) < len_total)
    {
        die(EINVAL, "arglist too long");
    }

    char** res = xalloc(len_total * sizeof (char*));
    char** resptr = res;
    while (*argv_a)
        *resptr++ = *argv_a++;

    while (*argv_b)
        *resptr++ = *argv_b++;

    *resptr = NULL;
    return res;
}

static char**
build_argv(const char* s0, ...)
{
    va_list args;
    size_t nr = 0;
    const char* s;

    s = s0;
    va_start(args, s0);
    while (s) {
        nr += 1;
        s = va_arg(args, const char*);
    }
    va_end(args);

    char** argv = xalloc(sizeof (*argv) * (nr + 1));
    char** argvp = argv;
    s = s0;
    va_start(args, s0);
    while (s) {
        *argvp++ = (char*) s;
        s = va_arg(args, const char*);
    }
    va_end(args);
    *argvp = NULL;
    return argv;
}

static struct child*
start_stub(int argc, char** argv, int* out_flags)
{
    int c;
    int flags = 0;
    char stubargbuf[16];
    char* stubarg = &stubargbuf[0];

    *stubarg++ = '-';

    static struct option opts[] = {
        { "help", no_argument, NULL, 'h' },
        { "local", no_argument, NULL, 'l' },
        { 0 }
    };

    while ((c = getopt_long(argc, argv, "+:lh", opts, NULL)) != -1) {
        switch (c) {
            case 'l':
                flags |= SHEX_LOCAL;
                break;
            case ':':
                die(EINVAL, "missing option for -%c", optopt);
            case '?':
                if (optopt != '?')
                    die(EINVAL, "invalid option -%c", optopt);
            case 'h':
                print_usage();
                return 0;
            default:
                abort();
        }
    }

    for (int i = 0; i < 3; ++i)
        if (isatty(i)) {
            xmkraw(i);
            *stubarg++ = '0' + i;
        }

    *stubarg++ = '\0';
    *out_flags = flags;

    argc -= optind;
    argv += optind;

    if (argc == 0)
        die(EINVAL, "no program given");

    if (flags & SHEX_LOCAL) {
        char** our_argv;

        if (strcmp(stubargbuf, "-") != 0) {
            our_argv = build_argv(orig_argv0, "stub", stubargbuf, "--", NULL);
        } else {
            our_argv = build_argv(orig_argv0, "stub", "--", NULL);
        }

        struct child_start_info csi = {
            .flags = (CHILD_INHERIT_STDERR | CHILD_NOCTTY),
            .exename = our_argv[0],
            .argv = (const char* const *) concat_argv(our_argv, argv),
        };

        return child_start(&csi);
    }

    abort(); // XXX: impl actual remote adb support
}

static void
shex_process_msg(struct adbx_sh* sh, struct msg mhdr)
{
    if (mhdr.type == MSG_CHILD_EXIT) {
        struct adbx_shex* shex = (struct adbx_shex*) sh;
        struct msg_child_exit m;
        read_cmdmsg(sh, mhdr, &m, sizeof (m));
        shex->child_exited = true;
        shex->child_exit_status = m.exit_status;
        return;
    }

    adbx_sh_process_msg(sh, mhdr);
}

#define CMD_BUFSZ 4096

static bool
fill_window_size(int fd, struct window_size* ws)
{
    int ret;
    struct winsize wz;

    do {
        ret = ioctl(fd, TIOCGWINSZ, &wz);
    } while (ret == -1 && errno == EINTR);

    if (ret != 0)
        return false;

    ws->row = wz.ws_row;
    ws->col = wz.ws_col;
    ws->xpixel = wz.ws_xpixel;
    ws->ypixel = wz.ws_ypixel;

    return ret == 0;
}

struct msg_shex_hello*
make_hello_msg(void)
{
    struct msg_shex_hello* m;
    size_t sz = sizeof (*m) + nr_termbits * sizeof (m->tctl[0]);
    m = xcalloc(sz);
    m->msg.type = MSG_SHEX_HELLO;
    m->version = PROTO_VERSION;
    m->maxmsg = CMD_BUFSZ;
    m->posix_vdisable_value = _POSIX_VDISABLE;

    struct term_control* tc = &m->tctl[0];
    struct termios in_attr;
    struct termios out_attr;

    int in_tty = -1;
    if (isatty(0)) {
        in_tty = 0;
        xtcgetattr(in_tty, &in_attr);
        m->ispeed = cfgetispeed(&in_attr);
    }

    int out_tty = -1;
    if (isatty(1))
        out_tty = 1;
    else if (isatty(2))
        out_tty = 2;

    if (out_tty != -1) {
        xtcgetattr(out_tty, &out_attr);
        m->ospeed = cfgetospeed(&out_attr);
        m->have_ws = fill_window_size(out_tty, &m->ws);
        dbg("ws %ux%u (%ux%u)",
            m->ws.row,
            m->ws.col,
            m->ws.xpixel,
            m->ws.ypixel);
    }

    for (unsigned i = 0; i < nr_termbits; ++i) {
        const struct termbit* tb = &termbits[i];
        if (in_tty != -1 && tb->thing == TERM_IFLAG)
            tc->value = !!(in_attr.c_iflag & tb->value);
        else if (in_tty != -1 && tb->thing == TERM_LFLAG)
            tc->value = !!(in_attr.c_lflag & tb->value);
        else if (in_tty != -1 && tb->thing == TERM_C_CC)
            tc->value = in_attr.c_cc[tb->value];
        else if (out_tty != -1 && tb->thing == TERM_OFLAG)
            tc->value = !!(out_attr.c_oflag & tb->value);
        else
            continue;

        snprintf(tc->name, sizeof (tc->name), "%s", tb->name);
        tc++;
    }

    m->msg.size = (char*) tc - (char*) m;
    return m;
}

static bool saw_sigwinch = false;
static void
handle_sigwinch(int signo)
{
    saw_sigwinch = true;
}

int
shex_main(int argc, char** argv)
{
    sigset_t orig_sigmask;
    sigset_t blocked_signals;
    sigemptyset(&blocked_signals);
    sigaddset(&blocked_signals, SIGWINCH);
    sigprocmask(SIG_BLOCK, &blocked_signals, &orig_sigmask);
    signal(SIGWINCH, handle_sigwinch);

    struct msg_shex_hello* hello_msg = make_hello_msg();

    if (isatty(0))
        hack_reopen_tty(0);

    if (isatty(1))
        hack_reopen_tty(1);

    if (isatty(2))
        hack_reopen_tty(2);

    int flags;
    struct child* child = start_stub(argc, argv, &flags);
    if (!child)
        return 0;

    write_all_adb_encoded(child->fd[0]->fd, hello_msg, hello_msg->msg.size);

    struct adbx_shex shex;
    memset(&shex, 0, sizeof (shex));
    struct adbx_sh* sh = &shex.sh;

    sh->poll_mask = &orig_sigmask;

    struct msg_stub_hello* stub_hello;
    struct msg* stub_hello_m = read_msg(child->fd[1]->fd, read_all);
    if (stub_hello_m->type != MSG_STUB_HELLO ||
        stub_hello_m->size < sizeof (*stub_hello))
    {
        die(ECOMM, "bad hello");
    }

    stub_hello = (struct msg_stub_hello*) stub_hello_m;
    sh->max_outgoing_msg = stub_hello->maxmsg;

    size_t proto_bufsz = CMD_BUFSZ;
    size_t child_bufsz = XXX_BUFSZ;

    sh->process_msg = shex_process_msg;
    sh->nrch = 5;
    struct channel** ch = xalloc(sh->nrch * sizeof (*ch));

    ch[FROM_PEER] = channel_new(child->fd[1], proto_bufsz, CHANNEL_FROM_FD);
    ch[FROM_PEER]->window = UINT32_MAX;

    ch[TO_PEER] = channel_new(child->fd[0], proto_bufsz, CHANNEL_TO_FD);

    ch[TO_PEER]->adb_encoding_hack = true;

    ch[CHILD_STDIN] = channel_new(fdh_dup(0),
                                  child_bufsz,
                                  CHANNEL_FROM_FD);
    ch[CHILD_STDIN]->track_window = true;

    ch[CHILD_STDOUT] = channel_new(fdh_dup(1), child_bufsz, CHANNEL_TO_FD);
    ch[CHILD_STDOUT]->track_bytes_written = true;
    ch[CHILD_STDOUT]->bytes_written =
        ringbuf_room(ch[CHILD_STDOUT]->rb);

    ch[CHILD_STDERR] = channel_new(fdh_dup(2), child_bufsz, CHANNEL_TO_FD);
    ch[CHILD_STDERR]->track_window = true;
    ch[CHILD_STDERR]->track_bytes_written = true;
    ch[CHILD_STDERR]->bytes_written =
        ringbuf_room(ch[CHILD_STDERR]->rb);

    sh->ch = ch;

    io_loop_init(sh);

    replace_with_dev_null(0);
    replace_with_dev_null(1);
    replace_with_dev_null(2);

    dbg("starting main loop");

    resume_loop:

    PUMP_WHILE(sh, (!saw_sigwinch &&
                    !shex.child_exited &&
                    !channel_dead_p(ch[FROM_PEER]) &&
                    !channel_dead_p(ch[TO_PEER])));

    if (saw_sigwinch) {
        dbg("SIGWINCH");
        struct msg_window_size m;
        memset(&m, 0, sizeof (m));
        m.msg.type = MSG_WINDOW_SIZE;
        m.msg.size = sizeof (m);
        int out_tty = -1;
        if (ch[CHILD_STDOUT]->fdh && isatty(ch[CHILD_STDOUT]->fdh->fd))
            out_tty = ch[CHILD_STDOUT]->fdh->fd;
        else if (ch[CHILD_STDERR]->fdh && isatty(ch[CHILD_STDERR]->fdh->fd))
            out_tty = ch[CHILD_STDERR]->fdh->fd;

        if (out_tty != -1 && fill_window_size(out_tty, &m.ws))
            queue_message_synch(sh, &m.msg);

        saw_sigwinch = false;
        goto resume_loop;
    }

    dbg("closing standard streams");

    channel_close(ch[CHILD_STDIN]);
    channel_close(ch[CHILD_STDOUT]);
    channel_close(ch[CHILD_STDERR]);

    PUMP_WHILE(sh, (!channel_dead_p(ch[CHILD_STDIN]) ||
                    !channel_dead_p(ch[CHILD_STDOUT]) ||
                    !channel_dead_p(ch[CHILD_STDERR])));

    if (!shex.child_exited)
        die(EPIPE, "lost connection to peer");

    return shex.child_exit_status;
}
