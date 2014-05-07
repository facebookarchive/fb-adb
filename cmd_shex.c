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
#include "ringbuf.h"
#include "proto.h"
#include "core.h"
#include "channel.h"

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

#define SHEX_DEBUG 0x1

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

static struct child*
start_stub(int argc, char** argv, int* out_flags)
{
    int c;
    int flags = 0;

    static struct option opts[] = {
        { "help", no_argument, NULL, 'h' },
        { "debug", no_argument, NULL, 'd' },
        { 0 }
    };

    while ((c = getopt_long(argc, argv, "+:dh", opts, NULL)) != -1) {
        switch (c) {
            case 'd':
                flags |= SHEX_DEBUG;
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

    *out_flags = flags;

    argc -= optind;
    argv += optind;

    if (argc == 0)
        die(EINVAL, "no program given");

    if (flags & SHEX_DEBUG) {
        const char** args = xcalloc((2 + 1 + argc) * sizeof (*args));
        args[0] = orig_argv0;
        args[1] = "stub";
        for (int i = 0; i <= argc; ++i)
            args[2 + i] = argv[i];

        return child_start((CHILD_INHERIT_STDERR | CHILD_NOCTTY),
                           args[0],
                           args);
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

int
shex_main(int argc, char** argv)
{
    int flags;
    struct child* child = start_stub(argc, argv, &flags);
    if (!child)
        return 0;

    struct adbx_shex shex;
    memset(&shex, 0, sizeof (shex));

    struct adbx_sh* sh = &shex.sh;
    size_t child_bufsz = 4096;
    size_t proto_bufsz = 8192;

    sh->process_msg = shex_process_msg;
    sh->max_outgoing_msg = proto_bufsz;
    sh->nrch = 5;
    struct channel** ch = xalloc(sh->nrch * sizeof (*ch));

    if (isatty(0))
        hack_reopen_tty(0);

    if (isatty(1))
        hack_reopen_tty(1);

    if (isatty(2))
        hack_reopen_tty(2);

    ch[FROM_PEER] = channel_new(child->fd[1], proto_bufsz, CHANNEL_FROM_FD);
    ch[FROM_PEER]->window = UINT32_MAX;
    ch[TO_PEER] = channel_new(child->fd[0], proto_bufsz, CHANNEL_TO_FD);

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
    if ((flags & SHEX_DEBUG) == 0)
        replace_with_dev_null(2);

    dbg("XXX 0");

    PUMP_WHILE(sh, (!shex.child_exited &&
                    !channel_dead_p(ch[FROM_PEER]) &&
                    !channel_dead_p(ch[TO_PEER])));

    dbg("XXX 1");

    channel_close(ch[CHILD_STDIN]);
    channel_close(ch[CHILD_STDOUT]);
    channel_close(ch[CHILD_STDERR]);

    dbg("XXX 2");

    PUMP_WHILE(sh, (!channel_dead_p(ch[CHILD_STDIN]) ||
                    !channel_dead_p(ch[CHILD_STDOUT]) ||
                    !channel_dead_p(ch[CHILD_STDERR])));

    if (!shex.child_exited)
        die(EPIPE, "lost connection to peer");

    return shex.child_exit_status;
}
