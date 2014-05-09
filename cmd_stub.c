#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include "util.h"
#include "child.h"
#include "xmkraw.h"
#include "ringbuf.h"
#include "ringbuf.h"
#include "proto.h"
#include "core.h"
#include "channel.h"
#include "adbenc.h"
#include "termbits.h"

static int
xwaitpid(pid_t child_pid)
{
    int status;
    int ret;

    do {
        ret = waitpid(child_pid, &status, 0);
    } while (ret < 0 && errno == EINTR);

    if (ret < 0)
        die_errno("waitpid(%lu)", (unsigned long) child_pid);

    return status;
}

static void
send_exit_message(int status, struct adbx_sh* sh)
{
    struct msg_child_exit m;
    memset(&m, 0, sizeof (m));
    m.msg.type = MSG_CHILD_EXIT;
    m.msg.size = sizeof (m);
    if (WIFEXITED(status))
        m.exit_status = WEXITSTATUS(status);
    else if (WIFSIGNALED(status))
        m.exit_status = 128 + WTERMSIG(status);

    queue_message_synch(sh, &m.msg);
}

static void
print_usage() {
    printf("%s CMD ARGS...: shex stub\n", prgname);
}

static void
set_window_size(int fd, const struct window_size* ws)
{
    int ret;
    struct winsize wz = {
        .ws_row = ws->row,
        .ws_col = ws->col,
        .ws_xpixel = ws->xpixel,
        .ws_ypixel = ws->ypixel,
    };

    do {
        ret = ioctl(fd, TIOCSWINSZ, &wz);
    } while (ret == -1 && errno == EINTR);
}

static void
setup_pty(int master, int slave, void* arg)
{
    struct msg_shex_hello* shex_hello = arg;
    char* hello_end = (char*) shex_hello + shex_hello->msg.size;
    struct termios attr = { 0 };
    xtcgetattr(slave, &attr);
    if (shex_hello->ispeed)
        cfsetispeed(&attr, shex_hello->ispeed);
    if (shex_hello->ospeed)
        cfsetospeed(&attr, shex_hello->ospeed);

    const struct termbit* tb = &termbits[0];
    const struct termbit* tb_end = tb + nr_termbits;
    struct term_control* tc = &shex_hello->tctl[0];

    while ((char*)(tc+1) <= hello_end && tb < tb_end) {
        int cmp = strncmp(tc->name, tb->name, sizeof (tc->name));
        if (cmp != 0) {
            dbg("tc not present: %.*s", (int)sizeof (tc->name), tc->name);
            if (cmp < 0) tc++; else tb++;
            continue;
        }

        tcflag_t* flg = NULL;
        if (tb->thing == TERM_IFLAG) {
            flg = &attr.c_iflag;
        } else if (tb->thing == TERM_OFLAG) {
            flg = &attr.c_oflag;
        } else if (tb->thing == TERM_LFLAG) {
            flg = &attr.c_lflag;
        } else if (tb->thing == TERM_C_CC) {
            if (tc->value == shex_hello->posix_vdisable_value)
                attr.c_cc[tb->value] = _POSIX_VDISABLE;
            else
                attr.c_cc[tb->value] = tc->value;

            dbg("c_cc[%s] = %d", tb->name, tc->value);
        }

        if (flg) {
            if (tc->value) {
                dbg("pty %s: set", tb->name);
                *flg |= tb->value;
            } else {
                dbg("pty %s: reset", tb->name);
                *flg &= ~tb->value;
            }
        }

        tc++;
        tb++;
    }

    xtcsetattr(slave, &attr);
    if (shex_hello->have_ws) {
        dbg("ws %ux%u (%ux%u)",
            shex_hello->ws.row,
            shex_hello->ws.col,
            shex_hello->ws.xpixel,
            shex_hello->ws.ypixel);
        set_window_size(slave, &shex_hello->ws);
    }
}

static struct child*
start_command_child(int argc,
                    char** argv,
                    struct msg_shex_hello* shex_hello)
{
    for (int i = 0; i < 3; ++i)
        if (fcntl(i, F_GETFL) < 0)
            die(EINVAL, "fd %d not open", i);

    int c;
    static struct option opts[] = {
        { "--help", no_argument, NULL, 'h' },
        { 0 }
    };

    int child_flags = 0;

    while ((c = getopt_long(argc, argv, "+:012h", opts, NULL)) != -1) {
        switch (c) {
            case '0':
                child_flags |= CHILD_PTY_STDIN;
                break;
            case '1':
                child_flags |= CHILD_PTY_STDOUT;
                break;
            case '2':
                child_flags |= CHILD_PTY_STDERR;
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
    if (argc < 1)
        die(EINVAL, "no command given");

    struct child_start_info csi = {
        .flags = child_flags,
        .exename = argv[0],
        .argv = (const char* const *) argv,
        .pty_setup = setup_pty,
        .pty_setup_data = shex_hello
    };

    return child_start(&csi);
}

struct stub {
    struct adbx_sh sh;
    struct child* child;
};

int
stub_main(int argc, char** argv)
{
    if (isatty(0)) {
        hack_reopen_tty(0);
        xmkraw(0);
    }

    if (isatty(1)) {
        hack_reopen_tty(1);
        xmkraw(1);
    }

    struct msg_shex_hello* shex_hello;
    struct msg* shex_hello_m = read_msg(0, read_all_adb_encoded);
    if (shex_hello_m->type != MSG_SHEX_HELLO ||
        shex_hello_m->size < sizeof (*shex_hello_m))
    {
        die(ECOMM, "bad hello");
    }

    shex_hello = (struct msg_shex_hello*) shex_hello_m;

    struct child* child = start_command_child(argc, argv, shex_hello);
    if (!child)
        return 0;

    struct stub stub;
    memset(&stub, 0, sizeof (stub));
    struct adbx_sh* sh = &stub.sh;
    size_t child_bufsz = XXX_BUFSZ;
    size_t proto_bufsz = XXX_BUFSZ;

    sh->process_msg = adbx_sh_process_msg;
    sh->max_outgoing_msg = shex_hello->maxmsg;
    sh->nrch = 5;
    struct channel** ch = xalloc(sh->nrch * sizeof (*ch));

    ch[FROM_PEER] = channel_new(fdh_dup(0),
                                proto_bufsz,
                                CHANNEL_FROM_FD);

    ch[FROM_PEER]->window = UINT32_MAX;
    ch[FROM_PEER]->adb_encoding_hack = true;

    ch[TO_PEER] = channel_new(fdh_dup(1), proto_bufsz, CHANNEL_TO_FD);


    ch[CHILD_STDIN] = channel_new(child->fd[0],
                                  child_bufsz,
                                  CHANNEL_TO_FD);

    ch[CHILD_STDIN]->track_bytes_written = true;
    ch[CHILD_STDIN]->bytes_written =
        ringbuf_room(ch[CHILD_STDIN]->rb);

    ch[CHILD_STDOUT] =
        channel_new(child->fd[1], child_bufsz, CHANNEL_FROM_FD);
    ch[CHILD_STDOUT]->track_window = true;

    ch[CHILD_STDERR] =
        channel_new(child->fd[2], child_bufsz, CHANNEL_FROM_FD);
    ch[CHILD_STDERR]->track_window = true;
    sh->ch = ch;

    io_loop_init(sh);

    PUMP_WHILE(sh, (!channel_dead_p(ch[FROM_PEER]) &&
                    !channel_dead_p(ch[TO_PEER]) &&
                    (!channel_dead_p(ch[CHILD_STDOUT]) ||
                     !channel_dead_p(ch[CHILD_STDERR]))));

    if (channel_dead_p(ch[FROM_PEER]) || channel_dead_p(ch[TO_PEER])) {
        //
        // If we lost our peer connection, make sure the child sees
        // SIGHUP instead of seeing its stdin close: just drain any
        // internally-buffered IO and exit.  When we lose the pty, the
        // child gets SIGHUP.
        //

        // Make sure we won't be getting any more commands.

        channel_close(ch[FROM_PEER]);
        channel_close(ch[TO_PEER]);

        PUMP_WHILE(sh, (!channel_dead_p(ch[FROM_PEER]) ||
                        !channel_dead_p(ch[TO_PEER])));

        // Drain output buffers
        channel_close(ch[CHILD_STDIN]);
        PUMP_WHILE(sh, !channel_dead_p(ch[CHILD_STDIN]));
        return 128 + SIGHUP;
    }

    //
    // Clean exit: close standard handles and drain IO.  Peer still
    // has no idea that we're exiting.  Get exit status, send that to
    // peer, then cleanly shut down the peer connection.
    //

    dbg("clean exit");

    channel_close(ch[CHILD_STDIN]);
    channel_close(ch[CHILD_STDOUT]);
    channel_close(ch[CHILD_STDERR]);

    PUMP_WHILE (sh, (!channel_dead_p(ch[CHILD_STDIN]) ||
                     !channel_dead_p(ch[CHILD_STDOUT]) ||
                     !channel_dead_p(ch[CHILD_STDERR])));

    send_exit_message(xwaitpid(child->pid), sh);
    channel_close(ch[TO_PEER]);

    PUMP_WHILE(sh, !channel_dead_p(ch[TO_PEER]));
    channel_close(ch[FROM_PEER]);
    PUMP_WHILE(sh, !channel_dead_p(ch[FROM_PEER]));
    return 0;
}
