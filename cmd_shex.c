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
#include "constants.h"
#include "adb.h"
#include "chat.h"
#include "stubs.h"
#include "timestamp.h"

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

static struct child*
start_stub_local(void)
{
    struct child_start_info csi = {
        .flags = CHILD_INHERIT_STDERR,
        .exename = orig_argv0,
        .argv = (const char*[]){orig_argv0, "stub", NULL},
    };

    struct child* child = child_start(&csi);
    char c;
    do {
        read_all(child->fd[1]->fd, &c, 1);
    } while (c != '\n');

    return child;
}

#ifndef BUILD_STUB
static void
send_stub(const void* data, size_t datasz)
{
    SCOPED_RESLIST(rl);
    const char* tmpfilename;
    FILE* tmpfile = xnamed_tempfile(&tmpfilename);
    if (fwrite(data, datasz, 1, tmpfile) != 1)
        die_errno("fwrite");
    if (fchmod(fileno(tmpfile), 0755) == -1)
        die_errno("fchmod");
    adb_send_file(tmpfilename, ADBX_REMOTE_FILENAME);
}
#endif

static struct child*
try_adb_stub(struct child_start_info* csi, char** err)
{
    struct reslist* rl_stub = reslist_push_new();
    struct child* child = child_start(csi);
    SCOPED_RESLIST(rl_local);
    struct chat* cc = chat_new(child->fd[0]->fd, child->fd[1]->fd);
    chat_swallow_prompt(cc);

    char* cmd = xaprintf("exec %s stub", ADBX_REMOTE_FILENAME);
    unsigned promptw = 40;
    if (strlen(cmd) > promptw) {
        // The extra round trip sucks, but if we don't do this, mksh's
        // helpful line editing will screw up our echo detection.
        chat_talk_at(cc, xaprintf("COLUMNS=%lu", promptw + strlen(cmd)));
        chat_swallow_prompt(cc);
    }

    chat_talk_at(cc, cmd);
    char* resp = chat_read_line(cc);
    dbg("stub resp: [%s]", resp);
    int n = -1;
    uint64_t ver;
    sscanf(resp, ADBX_PROTO_START_LINE "%n", &ver, &n);
    if (n == -1) {
        reslist_pop_nodestroy(rl_stub);
        *err = xstrdup(resp);
        reslist_destroy(rl_stub);
        return NULL;
    }

    if (ver < build_time) {
        reslist_pop_nodestroy(rl_stub);
        *err = xstrdup("build too old");
        reslist_destroy(rl_stub);
        return NULL;
    }

    reslist_pop_nodestroy(rl_stub);
    return child;
}

static struct child*
start_stub_adb(bool force_send_stub)
{
    struct child_start_info csi = {
        .flags = CHILD_INHERIT_STDERR,
        .exename = "adb",
        .argv = (const char*[]){"adb", "shell", NULL}
    };

    struct child* child = NULL;
    char* err = NULL;
    if (!force_send_stub)
        child = try_adb_stub(&csi, &err);

#ifndef BUILD_STUB
    if (!child) {
        send_stub(arm_stub, arm_stubsz);
        child = try_adb_stub(&csi, &err);
    }

    if (!child) {
        send_stub(x86_stub, x86_stubsz);
        child = try_adb_stub(&csi, &err);
    }
#endif

    if (!child)
        die(ECOMM, "trouble starting adb stub: %s", err);

    return child;
}

static void
shex_process_msg(struct adbx_sh* sh, struct msg mhdr)
{
    if (mhdr.type == MSG_CHILD_EXIT) {
        struct adbx_shex* shex = (struct adbx_shex*) sh;
        struct msg_child_exit m;
        read_cmdmsg(sh, mhdr, &m, sizeof (m));
        dbgmsg(&m.msg, "recv");
        shex->child_exited = true;
        shex->child_exit_status = m.exit_status;
        return;
    }

    adbx_sh_process_msg(sh, mhdr);
}

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
make_hello_msg(size_t cmd_bufsz,
               size_t stream_bufsz,
               size_t nr_argv)
{
    struct msg_shex_hello* m;
    size_t sz = sizeof (*m) + nr_termbits * sizeof (m->tctl[0]);
    m = xcalloc(sz);
    m->msg.type = MSG_SHEX_HELLO;
    m->version = build_time;
    m->nr_argv = nr_argv;
    m->maxmsg = cmd_bufsz;
    m->stub_send_bufsz = cmd_bufsz;
    m->stub_recv_bufsz = cmd_bufsz;
    for (int i = 0; i < 3; ++i) {
        m->si[i].bufsz = stream_bufsz;
        if (isatty(i)) {
            m->si[i].pty_p = true;
        }
    }

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

static void
send_cmdline_argument(int fd, unsigned type, const void* val, size_t valsz)
{
    struct msg m;
    size_t totalsz;
    if (SATADD(&totalsz, sizeof (m), valsz) || totalsz > UINT32_MAX)
        die(EINVAL, "command line argument too long");

    m.type = type;
    m.size = totalsz;
    write_all_adb_encoded(fd, &m, sizeof (m));
    write_all_adb_encoded(fd, val, valsz);
}

static void
send_cmdline(int fd, int argc, char** argv, const char* exename)
{
    if (argc == 0) {
        /* Default interactive shell */
        if (exename == NULL)
            send_cmdline_argument(fd, MSG_CMDLINE_DEFAULT_SH, NULL, 0);
        else
            send_cmdline_argument(fd, MSG_CMDLINE_ARGUMENT,
                                  exename, strlen(exename));

        send_cmdline_argument(fd, MSG_CMDLINE_DEFAULT_SH_LOGIN, NULL, 0);
    } else {
        if (exename == NULL)
            exename = argv[0];

        send_cmdline_argument(fd, MSG_CMDLINE_ARGUMENT,
                              exename, strlen(exename));

        for (int i = 0; i < argc; ++i)
            send_cmdline_argument(fd, MSG_CMDLINE_ARGUMENT,
                                  argv[i], strlen(argv[i]));
    }
}

int
shex_main(int argc, char** argv)
{
    size_t cmd_bufsz = DEFAULT_CMD_BUFSZ;
    size_t child_stream_bufsz = DEFAULT_STREAM_BUFSZ;
    size_t our_stream_bufsz = DEFAULT_STREAM_BUFSZ;
    bool local_mode = false;

    sigset_t orig_sigmask;
    sigset_t blocked_signals;
    const char* exename = NULL;
    bool force_send_stub = false;

    sigemptyset(&blocked_signals);
    sigaddset(&blocked_signals, SIGWINCH);
    sigprocmask(SIG_BLOCK, &blocked_signals, &orig_sigmask);
    signal(SIGWINCH, handle_sigwinch);

    if (isatty(0))
        hack_reopen_tty(0);

    if (isatty(1))
        hack_reopen_tty(1);

    if (isatty(2))
        hack_reopen_tty(2);

    static struct option opts[] = {
        { "help", no_argument, NULL, 'h' },
        { "local", no_argument, NULL, 'l' },
        { "exename", required_argument, NULL, 'e' },
        { "force-send-stub", no_argument, NULL, 'f' },
        { 0 }
    };

    char c;
    while ((c = getopt_long(argc, argv, "+:lhe:f", opts, NULL)) != -1) {
        switch (c) {
            case 'e':
                exename = optarg;
                break;
            case 'f':
                force_send_stub = true;
                break;
            case 'l':
                local_mode = true;
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

    argc -= optind;
    argv += optind;
    size_t args_to_send = XMAX((size_t) argc + 1, 2);
    struct msg_shex_hello* hello_msg =
        make_hello_msg(cmd_bufsz, child_stream_bufsz, args_to_send);

    struct child* child;
    if (local_mode)
        child = start_stub_local();
    else
        child = start_stub_adb(force_send_stub);

    write_all_adb_encoded(child->fd[0]->fd, hello_msg, hello_msg->msg.size);
    send_cmdline(child->fd[0]->fd, argc, argv, exename);

    struct adbx_shex shex;
    memset(&shex, 0, sizeof (shex));
    struct adbx_sh* sh = &shex.sh;

    sh->poll_mask = &orig_sigmask;
    sh->max_outgoing_msg = cmd_bufsz;
    sh->process_msg = shex_process_msg;
    sh->nrch = 5;
    struct channel** ch = xalloc(sh->nrch * sizeof (*ch));

    ch[FROM_PEER] = channel_new(child->fd[1], cmd_bufsz, CHANNEL_FROM_FD);
    ch[FROM_PEER]->window = UINT32_MAX;

    ch[TO_PEER] = channel_new(child->fd[0], cmd_bufsz, CHANNEL_TO_FD);
    ch[TO_PEER]->adb_encoding_hack = true;

    ch[CHILD_STDIN] = channel_new(fdh_dup(0),
                                  our_stream_bufsz,
                                  CHANNEL_FROM_FD);
    ch[CHILD_STDIN]->track_window = true;

    ch[CHILD_STDOUT] = channel_new(fdh_dup(1),
                                   our_stream_bufsz,
                                   CHANNEL_TO_FD);
    ch[CHILD_STDOUT]->track_bytes_written = true;
    ch[CHILD_STDOUT]->bytes_written =
        ringbuf_room(ch[CHILD_STDOUT]->rb);

    ch[CHILD_STDERR] = channel_new(fdh_dup(2),
                                   our_stream_bufsz,
                                   CHANNEL_TO_FD);
    ch[CHILD_STDERR]->track_window = true;
    ch[CHILD_STDERR]->track_bytes_written = true;
    ch[CHILD_STDERR]->bytes_written =
        ringbuf_room(ch[CHILD_STDERR]->rb);

    sh->ch = ch;

    for (int i = 0; i <3; ++i)
        if (isatty(i))
            xmkraw(i, 0);

    replace_with_dev_null(0);
    replace_with_dev_null(1);

    io_loop_init(sh);
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
