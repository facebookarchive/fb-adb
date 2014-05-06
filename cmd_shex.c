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
#include "util.h"
#include "child.h"
#include "xmkraw.h"
#include "ringbuf.h"
#include "proto.h"
#include "core.h"
#include "channel.h"

static void
connect_peer_unix(const char* sockname, int* from_peer, int* to_peer)
{
    *from_peer = xsocket(AF_UNIX, SOCK_STREAM, 0);
    xconnect(*from_peer, xsockaddr_unix(sockname));
    *to_peer = xdup(*from_peer);
}

static void
print_usage(void)
{
    printf("%s [-u sock]: shex\n", prgname);
}

struct adbx_shex {
    struct adbx_sh sh;
};

int
shex_main(int argc, char** argv)
{
    int c;
    int from_peer = -1;
    int to_peer = -1;
    static struct option opts[] = {
        {"unix-peer", required_argument, 0, 'u' },
    };

    while ((c = getopt_long(argc, argv, ":u:h?", opts, NULL)) != -1) {
        switch (c) {
            case 'u':
                if (from_peer != -1 || to_peer != -1)
                    die(EINVAL, "already connected");

                connect_peer_unix(optarg, &from_peer, &to_peer);
                break;
            case 'h':
            case '?':
                print_usage();
                return 0;
            default:
                die(EINVAL, "invalid option %c", optopt);
        }
    }

    struct adbx_shex shex;
    memset(&shex, 0, sizeof (shex));
    struct adbx_sh* sh = &stub.sh;
    size_t child_bufsz = 4096;
    size_t proto_bufsz = 8192;

    sh->process_msg = adbx_sh_process_msg;
    sh->max_outgoing_msg = proto_bufsz;
    sh->nrch = 5;
    struct channel** ch = xalloc(sh->nrch * sizeof (*ch));

    ch[FROM_PEER] = channel_new(fdh_dup(from_peer),
                                proto_bufsz,
                                CHANNEL_FROM_FD);

    ch[FROM_PEER]->track_window = false;
    ch[FROM_PEER]->window = UINT32_MAX;

    ch[TO_PEER] = channel_new(fdh_dup(to_peer), proto_bufsz, CHANNEL_TO_FD);

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


    return 1;
}
