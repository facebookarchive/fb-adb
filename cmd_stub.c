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

struct adbx_stub {
    struct adbx_sh sh;
    struct child* child;
};

static int
xwaitpid(pid_t child_pid)
{
    int status;
    for (;;) {
        if (waitpid(child_pid, &status, 0) < 0 && errno != EINTR)
            die_errno("waitpid(%lu)", (unsigned long) child_pid);
    }

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
stdio_from_unix_peer(const char* path)
{
    SCOPED_RESLIST(rl_unixconn);
    struct xsockaddr* xa = xsockaddr_unix(path);
    int serverfd = xsocket(AF_UNIX, SOCK_STREAM, 0);
    xbind(serverfd, xa);
    if (listen(serverfd, 1) < 0)
        die_errno("listen");

    int clientfd = xaccept(serverfd);
    if (dup2(clientfd, 0) < 0 || dup2(clientfd, 1) < 0)
        die_errno("dup to stdin/stdout");
}

static void
print_usage() {
    printf("%s [-u peer] CMD ARGS...: shex stub\n", prgname);
}

int
stub_main(int argc, char** argv)
{
    for (int i = 0; i < 3; ++i)
        if (fcntl(i, F_GETFL) < 0)
            die(EINVAL, "fd %d not open", i);

    int c;
    const char* unix_peer = NULL;
    static struct option opts[] = {
        {"unix-peer", required_argument, 0, 'u' },
    };

    while ((c = getopt_long(argc, argv, ":u:h?", opts, NULL)) != -1) {
        switch (c) {
            case 'u':
                unix_peer = optarg;
                break;
            case 'h':
            case '?':
                print_usage();
                return 0;
            default:
                die(EINVAL, "invalid option %c", optopt);
        }
    }

    argc -= optind;
    argv += optind;
    if (argc < 1)
        die(EINVAL, "no command given");

    if (unix_peer)
        stdio_from_unix_peer(unix_peer);

    struct child* child =
        child_start((CHILD_PTY_STDIN |
                     CHILD_PTY_STDOUT |
                     CHILD_PTY_STDERR ),
                    argv[0],
                    (const char* const*) argv);

    if (isatty(0)) xmkraw(0);
    if (isatty(1)) xmkraw(1);

    struct adbx_stub stub;
    memset(&stub, 0, sizeof (stub));
    struct adbx_sh* sh = &stub.sh;
    size_t child_bufsz = 4096;
    size_t proto_bufsz = 8192;

    stub.child = child;
    sh->process_msg = adbx_sh_process_msg;
    sh->max_outgoing_msg = proto_bufsz;
    sh->nrch = 5;
    struct channel** ch = xalloc(sh->nrch * sizeof (*ch));

    ch[FROM_PEER] = channel_new(fdh_dup(0),
                                proto_bufsz,
                                CHANNEL_FROM_FD);

    ch[FROM_PEER]->track_window = false;
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

    bool peer_dead = false;

    while ((!channel_dead_p(ch[CHILD_STDOUT]) ||
            !channel_dead_p(ch[CHILD_STDERR])))
    {
        peer_dead = (channel_dead_p(ch[FROM_PEER]) ||
                     channel_dead_p(ch[TO_PEER]));

        if (peer_dead)
            break;

        io_loop_1(sh);
    }

    if (peer_dead) {
        //
        // If we lost our peer connection, make sure the child sees
        // SIGHUP instead of seeing its stdin close: just drain any
        // internally-buffered IO and exit.  When we lose the pty, the
        // child gets SIGHUP.
        //

        // Make sure we won't be getting any more commands.

        channel_close(ch[FROM_PEER]);
        channel_close(ch[TO_PEER]);
        while (!channel_dead_p(ch[FROM_PEER]) ||
               !channel_dead_p(ch[TO_PEER]))
        {
            io_loop_1(sh);
        }

        // Drain output buffers
        channel_close(ch[CHILD_STDIN]);
        while (!channel_dead_p(ch[CHILD_STDIN]))
            io_loop_1(sh);

        return 128 + SIGHUP;
    }

    //
    // Clean exit: close standard handles and drain IO.  Peer still
    // has no idea that we're exiting.  Get exit status, send that to
    // peer, then cleanly shut down the peer connection.
    //

    channel_close(ch[CHILD_STDIN]);
    channel_close(ch[CHILD_STDOUT]);
    channel_close(ch[CHILD_STDERR]);

    while (!channel_dead_p(ch[CHILD_STDIN]) ||
           !channel_dead_p(ch[CHILD_STDOUT]) ||
           !channel_dead_p(ch[CHILD_STDERR]))
    {
        io_loop_1(sh);
    }

    send_exit_message(xwaitpid(child->pid), sh);
    channel_close(ch[TO_PEER]);

    while (!channel_dead_p(ch[TO_PEER]))
        io_loop_1(sh);

    channel_close(ch[FROM_PEER]);
    while (!channel_dead_p(ch[FROM_PEER]))
        io_loop_1(sh);

    return 0;
}
