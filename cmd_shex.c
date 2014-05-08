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
#include "xmkraw.h"

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

        char** stub_argv = concat_argv(our_argv, argv);
        return child_start((CHILD_INHERIT_STDERR | CHILD_NOCTTY),
                           stub_argv[0], (const char* const*) stub_argv);
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

    struct adbx_shex shex;
    memset(&shex, 0, sizeof (shex));

    struct adbx_sh* sh = &shex.sh;
    size_t child_bufsz = XXX_BUFSZ;
    size_t proto_bufsz = XXX_BUFSZ;

    sh->process_msg = shex_process_msg;
    sh->max_outgoing_msg = proto_bufsz;
    sh->nrch = 5;
    struct channel** ch = xalloc(sh->nrch * sizeof (*ch));


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
    replace_with_dev_null(2);

    dbg("starting main loop");

    PUMP_WHILE(sh, (!shex.child_exited &&
                    !channel_dead_p(ch[FROM_PEER]) &&
                    !channel_dead_p(ch[TO_PEER])));

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
