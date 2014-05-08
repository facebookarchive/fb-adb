#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <getopt.h>
#include "util.h"
#include "child.h"
#include "xmkraw.h"
#include "ringbuf.h"
#include "ringbuf.h"
#include "proto.h"
#include "core.h"
#include "channel.h"

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

static struct child*
start_command_child(int argc, char** argv)
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

    return child_start(child_flags, argv[0], (const char* const*) argv);
}

struct stub {
    struct adbx_sh sh;
    struct child* child;
};

int
stub_main(int argc, char** argv)
{
    struct child* child = start_command_child(argc, argv);
    if (!child)
        return 0;

    if (isatty(0)) {
        hack_reopen_tty(0);
        xmkraw(0);
    }

    if (isatty(1)) {
        hack_reopen_tty(1);
        xmkraw(1);
    }

    struct stub stub;
    memset(&stub, 0, sizeof (stub));
    struct adbx_sh* sh = &stub.sh;
    size_t child_bufsz = XXX_BUFSZ;
    size_t proto_bufsz = XXX_BUFSZ;

    sh->process_msg = adbx_sh_process_msg;
    sh->max_outgoing_msg = proto_bufsz;
    sh->nrch = 5;
    struct channel** ch = xalloc(sh->nrch * sizeof (*ch));

    ch[FROM_PEER] = channel_new(fdh_dup(0),
                                proto_bufsz,
                                CHANNEL_FROM_FD);

    ch[FROM_PEER]->window = UINT32_MAX;

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
