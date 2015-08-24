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
#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>

#ifdef __ANDROID__
#include <sys/system_properties.h>
#include <android/log.h>
#define LOG_TAG PACKAGE
#endif

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
#include "constants.h"
#include "timestamp.h"
#include "cmd_stub.h"
#include "net.h"
#include "xenviron.h"

static bool should_send_error_packet = false;

static void
send_exit_message(int status, struct fb_adb_sh* sh)
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

    dbg("TIOCSWINSZ(%ux%u): %d", wz.ws_row, wz.ws_col, ret);
}

struct stub {
    struct fb_adb_sh sh;
    struct child* child;
};

static void
stub_process_msg(struct fb_adb_sh* sh, struct msg mhdr)
{
    if (mhdr.type == MSG_WINDOW_SIZE) {
        struct msg_window_size m;
        read_cmdmsg(sh, mhdr, &m, sizeof (m));
        dbgmsg(&m.msg, "recv");
        struct stub* stub = (struct stub*) sh;
        if (stub->child->pty_master)
            set_window_size(stub->child->pty_master->fd, &m.ws);

        return;
    }

    fb_adb_sh_process_msg(sh, mhdr);
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
        if (cmp < 0) {
            dbg("tc not present: %.*s", (int) sizeof (tc->name), tc->name);
            tc++;
            continue;
        }

        if (cmp > 0) {
            dbg("tc not sent: %s", tb->name);
            tb++;
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
        set_window_size(master, &shex_hello->ws);
    }
}

static void*
check_msg_cast(struct msg* h, size_t minimum_size)
{
    if (h->size < minimum_size) {
        die(ECOMM,
            "bad handshake: short message:"
            "type=%u expected=%u received=%u",
            (unsigned) h->type,
            (unsigned) minimum_size,
            (unsigned) h->size);
    }

    return h;
}

#define CHECK_MSG_CAST(_mhdr, _type) \
    ((_type *) check_msg_cast((_mhdr), sizeof (_type)))

static void
die_setup_eof(void)
{
    die(ECOMM, "peer disconnected");
}

static void
die_setup_overflow(void)
{
    die(ECOMM, "bad handshake: length too big");
}

static void
read_child_arglist(reader rdr,
                   size_t expected,
                   char*** out_argv,
                   const char** out_cwd,
                   struct xenviron** out_xe)
{
    char** argv;
    const char* cwd = NULL;
    struct xenviron* xe = NULL;

    if (expected >= SIZE_MAX / sizeof (*argv))
        die(EFBIG, "too many arguments");

    argv = xalloc(sizeof (*argv) * (1+expected));
    size_t argno = 0;
    while (argno < expected) {
        SCOPED_RESLIST(rl_read_arg);
        struct msg* mhdr = read_msg(0, rdr);
        const char* argval = NULL;
        size_t arglen;

        if (mhdr->type == MSG_CMDLINE_ARGUMENT) {
            struct msg_cmdline_argument* m =
                CHECK_MSG_CAST(mhdr, struct msg_cmdline_argument);
            argval = m->value;
            arglen = m->msg.size - sizeof (*m);
        } else if (mhdr->type == MSG_CMDLINE_DEFAULT_SH ||
                   mhdr->type == MSG_CMDLINE_DEFAULT_SH_LOGIN)
        {
            argval = getenv("SHELL");
            if (argval == NULL)
                argval = DEFAULT_SHELL;

            if (mhdr->type == MSG_CMDLINE_DEFAULT_SH_LOGIN)
                argval = xaprintf("-%s", argval);

            arglen = strlen(argval);
        } else if (mhdr->type == MSG_CMDLINE_ARGUMENT_JUMBO) {
            struct msg_cmdline_argument_jumbo* mj =
                CHECK_MSG_CAST(mhdr, struct msg_cmdline_argument_jumbo);

            arglen = mj->actual_size;
            void* buf = xalloc(arglen);
            size_t nr_read = rdr(0, buf, arglen);
            if (nr_read != arglen)
                die_setup_eof();
            argval = buf;
        } else if (mhdr->type == MSG_CLEARENV) {
            if (xe) {
                xenviron_clear(xe);
            } else {
                WITH_CURRENT_RESLIST(rl_read_arg->parent);
                xe = xenviron_create(NULL);
            }
        } else if (mhdr->type == MSG_ENVIRONMENT_VARIABLE_SET) {
            struct msg_environment_variable_set* e =
                CHECK_MSG_CAST(mhdr, struct msg_environment_variable_set);
            const char* payload = e->value;
            size_t payload_length = e->msg.size - sizeof (*e);
            const char* name;
            const char* value;
            size_t name_length = strnlen(payload, payload_length);

            if (name_length == payload_length)
                die(ECOMM, "invalid environment variable messsage");

            name = payload;
            size_t value_offset = name_length + 1;
            value = xstrndup(payload + value_offset,
                             payload_length - value_offset);

            if (xe == NULL) {
                WITH_CURRENT_RESLIST(rl_read_arg->parent);
                xe = xenviron_copy_environ();
            }
            xenviron_set(xe, name, value);
        } else if (mhdr->type == MSG_ENVIRONMENT_VARIABLE_SET_JUMBO) {
            struct msg_environment_variable_set_jumbo* ej =
                CHECK_MSG_CAST(
                    mhdr,
                    struct msg_environment_variable_set_jumbo);

            if (ej->name_length == SIZE_MAX || ej->value_length == SIZE_MAX)
                die_setup_overflow();

            char* name = xalloc((size_t) ej->name_length + 1);
            char* value = xalloc((size_t) ej->value_length + 1);

            if (rdr(0, name, ej->name_length) < ej->name_length ||
                rdr(0, value, ej->value_length) < ej->value_length)
                die_setup_eof();

            name[ej->name_length] = '\0';
            value[ej->value_length] = '\0';

            if (xe == NULL) {
                WITH_CURRENT_RESLIST(rl_read_arg->parent);
                xe = xenviron_copy_environ();
            }
            xenviron_set(xe, name, value);
        } else if (mhdr->type == MSG_ENVIRONMENT_VARIABLE_UNSET) {
            struct msg_environment_variable_unset* ue =
                CHECK_MSG_CAST(mhdr, struct msg_environment_variable_unset);
            const char* payload = ue->name;
            size_t payload_length = ue->msg.size - sizeof (*ue);

            if (xe == NULL) {
                WITH_CURRENT_RESLIST(rl_read_arg->parent);
                xe = xenviron_copy_environ();
            }
            xenviron_unset(xe, xstrndup(payload, payload_length));
        } else if (mhdr->type == MSG_ENVIRONMENT_VARIABLE_UNSET_JUMBO) {
            struct msg_environment_variable_unset_jumbo* uej =
                CHECK_MSG_CAST(
                    mhdr,
                    struct msg_environment_variable_unset_jumbo);

            if (uej->name_length == SIZE_MAX)
                die_setup_overflow();

            char* name = xalloc((size_t) uej->name_length + 1);
            if (rdr(0, name, uej->name_length) < uej->name_length)
                die_setup_eof();

            name[uej->name_length] = '\0';
            if (xe == NULL) {
                WITH_CURRENT_RESLIST(rl_read_arg->parent);
                xe = xenviron_copy_environ();
            }
            xenviron_unset(xe, name);
        } else if (mhdr->type == MSG_CHDIR) {
            struct msg_chdir* mchd = CHECK_MSG_CAST(mhdr, struct msg_chdir);
            WITH_CURRENT_RESLIST(rl_read_arg->parent);
            cwd = xstrndup(mchd->dir, mhdr->size - sizeof (*mchd));
        } else {
            die(ECOMM,
                "bad handshake: unknown init msg s=%u t=%u",
                (unsigned) mhdr->size, (unsigned) mhdr->type);
        }

        if (argval != NULL) {
            WITH_CURRENT_RESLIST(rl_read_arg->parent);
            size_t allocsz;
            if (SATADD(&allocsz, arglen, 1))
                die_setup_overflow();

            argv[argno] = xalloc(arglen + 1);
            memcpy(argv[argno], argval, arglen);
            argv[argno][arglen] = '\0';

            argno += 1;
        }
    }

    argv[expected] = NULL;
    *out_argv = argv;
    *out_cwd = cwd;
    *out_xe = xe;
}

static struct child*
start_child(reader rdr, struct msg_shex_hello* shex_hello)
{
    if (shex_hello->nr_argv < 2)
        die(ECOMM, "insufficient arguments given");

    SCOPED_RESLIST(rl_args);
    char** child_args;
    const char* child_chdir = NULL;
    struct xenviron* child_xe = NULL;
    read_child_arglist(rdr,
                       shex_hello->nr_argv,
                       &child_args,
                       &child_chdir,
                       &child_xe);

    WITH_CURRENT_RESLIST(rl_args->parent);

    struct child_start_info csi = {
        .flags = CHILD_SETSID,
        .exename = child_args[0],
        .argv = (const char* const *) child_args + 1,
        .environ = child_xe ? xenviron_as_environ(child_xe) : NULL,
        .pty_setup = setup_pty,
        .pty_setup_data = shex_hello,
        .deathsig = -SIGHUP,
        .child_chdir = child_chdir,
    };

    if (shex_hello->si[0].pty_p)
        csi.flags |= CHILD_PTY_STDIN;
    if (shex_hello->si[1].pty_p)
        csi.flags |= CHILD_PTY_STDOUT;
    if (shex_hello->si[2].pty_p)
        csi.flags |= CHILD_PTY_STDERR;

    if (shex_hello->stdio_socket_p)
        csi.flags |= CHILD_SOCKETPAIR_STDIO;

    if (shex_hello->ctty_p)
        csi.flags |= CHILD_CTTY;

    return child_start(&csi);
}

static void __attribute__((noreturn))
re_exec_as_root()
{
    should_send_error_packet = false; // Peer expects text
    execlp("su", "su", "-c", orig_argv0, "stub", NULL);
    die_errno("execlp of su");
}

#ifdef __ANDROID__
static unsigned
api_level()
{
    static unsigned cached_api_level;
    unsigned api_level = cached_api_level;
    if (api_level == 0) {
        char api_level_str[PROP_VALUE_MAX];
        if (__system_property_get("ro.build.version.sdk", api_level_str) == 0)
            die(ENOENT, "cannot query system API level");

        api_level = cached_api_level = (unsigned) atoi(api_level_str);
    }

    return api_level;
}
#else
static unsigned
api_level()
{
    return 15; // Fake it
}
#endif

static void __attribute__((noreturn))
re_exec_as_user(const char* username, bool shell_thunk)
{
    should_send_error_packet = false; // Peer expects text
    (void) shell_thunk;
#ifdef __ANDROID__
    if (!shell_thunk) {
        execlp("run-as", "run-as", username, orig_argv0, "stub", NULL);
    } else {
        // Work around brain-damaged SELinux-based security theater
        // that prohibits execution of binaries directly from
        // /data/local/tmp on Lollipop and above.  Instead, copy the
        // binary to the application data directory (which is the
        // current woring directory for processes launched via run-as)
        // and run that copy.

        // Small shell script we run below.  $1 is the name of the
        // fb-adb binary; the rest of the arguments are arguments for
        // fb-adb.
        static const char selinux_workaround[] =
            "{ { [ -f fb-adb ] && cmp fb-adb \"$1\" >/dev/null 2>&1; } "
            "  || { cp -f \"$1\" fb-adb.tmp.$$ && mv -f fb-adb.tmp.$$ fb-adb; }"
            " } && shift && exec ./fb-adb \"$@\"";

        execlp("run-as", "run-as", username,
               "/system/bin/sh",
               "-c",
               selinux_workaround,
               "selinux_workaround",
               orig_argv0,
               "stub",
               NULL);
    }

    die_errno("execlp of run-as");
#else
    die(ENOSYS, "re_exec_as_user works only under Android");
#endif
}

static void
send_socket_available_now_message()
{
    struct msg m;
    memset(&m, 0, sizeof (m));
    m.type = MSG_LISTENING_ON_SOCKET;
    m.size = sizeof (m);
    write_all(1, &m, sizeof (m));
}

static int
connect_peer_unix_socket(struct msg* mhdr)
{
    struct msg_rebind_to_unix_socket* rbmsg =
        (struct msg_rebind_to_unix_socket*) mhdr;

    if (rbmsg->msg.size < sizeof (*rbmsg))
        die(ECOMM, "invalid MSG_REBIND_TO_UNIX_SOCKET length");

    size_t socket_name_length = rbmsg->msg.size - sizeof (*rbmsg);
    char* socket_name = strndup(rbmsg->socket, socket_name_length);
    int listening_socket = xsocket(AF_UNIX, SOCK_STREAM, 0);

    xbind(listening_socket, make_addr_unix_abstract(
              socket_name, strlen(socket_name)));

    if (listen(listening_socket, 1) == -1)
        die_errno("listen");

    send_socket_available_now_message();
    return xaccept(listening_socket);
}

static int
connect_peer_tcp4_socket(struct msg* mhdr)
{
    struct msg_rebind_to_tcp4_socket* rbmsg =
        (struct msg_rebind_to_tcp4_socket*) mhdr;

    if (rbmsg->msg.size < sizeof (*rbmsg))
        die(ECOMM, "invalid MSG_REBIND_TO_TCP4_SOCKET length");

    int client = xsocket(AF_INET, SOCK_STREAM, 0);
    disable_tcp_nagle(client);

    struct addr addr;
    memset(&addr, 0, sizeof (addr));
    addr.size = sizeof (addr.addr_in);
    addr.addr_in.sin_family = AF_INET;
    addr.addr_in.sin_port = rbmsg->port;
    addr.addr_in.sin_addr.s_addr = rbmsg->addr;
    xconnect(client, &addr);
    return client;
}

static int
connect_peer_tcp6_socket(struct msg* mhdr)
{
    struct msg_rebind_to_tcp6_socket* rbmsg =
        (struct msg_rebind_to_tcp6_socket*) mhdr;

    if (rbmsg->msg.size < sizeof (*rbmsg))
        die(ECOMM, "invalid MSG_REBIND_TO_TCP6_SOCKET length");

    int client = xsocket(AF_INET, SOCK_STREAM, 0);
    disable_tcp_nagle(client);

    struct addr addr;
    memset(&addr, 0, sizeof (addr));
    addr.size = sizeof (addr.addr_in6);
    addr.addr_in6.sin6_family = AF_INET6;
    addr.addr_in6.sin6_port = rbmsg->port;
    memcpy(addr.addr_in6.sin6_addr.s6_addr, rbmsg->addr, 16);
    xconnect(client, &addr);
    return client;
}

static void
rebind_to_socket(struct msg* mhdr)
{
    SCOPED_RESLIST(rl_rebind);
    int client;

    switch (mhdr->type) {
        case MSG_REBIND_TO_UNIX_SOCKET:
            client = connect_peer_unix_socket(mhdr);
            break;
        case MSG_REBIND_TO_TCP4_SOCKET:
            client = connect_peer_tcp4_socket(mhdr);
            break;
        case MSG_REBIND_TO_TCP6_SOCKET:
            client = connect_peer_tcp6_socket(mhdr);
            break;
        default:
            assert(!"missed socket message enumeration");
            __builtin_unreachable();
    }

    // Leak the old console file descriptor so our parent doesn't
    // think we're died.  Deliberately allow the file descriptor to
    // leak across exec.
    int leaked = dup(2);
    if (leaked == -1)
        die_errno("dup");

    xdup3nc(client, 0, 0);
    xdup3nc(client, 1, 0);
    xdup3nc(client, 2, 0);
}

struct main_args {
    int argc;
    const char** argv;
    int result;
};

static int
stub_main_1(int argc, const char** argv)
{
    /* XMKRAW_SKIP_CLEANUP so we never change from raw back to cooked
     * mode on exit.  The connection dies on exit anyway, and
     * resetting the pty can send some extra bytes that can confuse
     * our peer. */

    if (isatty(0))
        xmkraw(0, XMKRAW_SKIP_CLEANUP);

    if (isatty(1))
        xmkraw(1, XMKRAW_SKIP_CLEANUP);

    printf(FB_ADB_PROTO_START_LINE "\n", build_time,
           (int) getuid(), (unsigned) api_level());
    fflush(stdout);

    should_send_error_packet = true;

    struct msg_shex_hello* shex_hello;
    reader rdr = read_all_adb_encoded;

    if (!isatty(0))
        rdr = read_all;

    struct msg* mhdr = read_msg(0, rdr);

    if (mhdr->type == MSG_REBIND_TO_UNIX_SOCKET ||
        mhdr->type == MSG_REBIND_TO_TCP4_SOCKET ||
        mhdr->type == MSG_REBIND_TO_TCP6_SOCKET)
    {
        rebind_to_socket(mhdr);
        rdr = read_all; // Yay! No more tty deobfuscation!
        mhdr = read_msg(0, rdr);
    }

    if (mhdr->type == MSG_EXEC_AS_ROOT)
        re_exec_as_root(); // Never returns

    if (mhdr->type == MSG_EXEC_AS_USER) {
        struct msg_exec_as_user* umsg =
            (struct msg_exec_as_user*) mhdr;
        size_t username_length = umsg->msg.size - sizeof (*umsg);
        const char* username = xstrndup(umsg->username, username_length);
        re_exec_as_user(username, umsg->shell_thunk); // Never returns
    }

    if (mhdr->type != MSG_SHEX_HELLO ||
        mhdr->size < sizeof (struct msg_shex_hello))
    {
        die(ECOMM, "bad hello");
    }

    shex_hello = (struct msg_shex_hello*) mhdr;

    struct child* child = start_child(rdr, shex_hello);

    // Child could be running arbitrary SIGHUP-ignoring code.  Do our
    // best to kill it if we have to exit, but don't wait around
    // for it.
    child->skip_cleanup_wait = true;

    struct stub stub;
    memset(&stub, 0, sizeof (stub));
    stub.child = child;
    struct fb_adb_sh* sh = &stub.sh;

    sh->process_msg = stub_process_msg;
    sh->max_outgoing_msg = shex_hello->maxmsg;
    sh->nrch = 5;
    struct channel** ch = xalloc(sh->nrch * sizeof (*ch));

    should_send_error_packet = false;

    ch[FROM_PEER] = channel_new(fdh_dup(0),
                                shex_hello->stub_recv_bufsz,
                                CHANNEL_FROM_FD);

    ch[FROM_PEER]->window = UINT32_MAX;
    ch[FROM_PEER]->adb_encoding_hack = !!(rdr == read_all_adb_encoded);
    replace_with_dev_null(0);

    ch[TO_PEER] = channel_new(fdh_dup(1),
                              shex_hello->stub_send_bufsz,
                              CHANNEL_TO_FD);
    replace_with_dev_null(1);

    // See comment in cmd_shex.c
    ch[TO_PEER]->always_buffer = true;

    ch[CHILD_STDIN] = channel_new(child->fd[0],
                                  shex_hello->si[0].bufsz,
                                  CHANNEL_TO_FD);

    if (shex_hello->si[0].compress)
        ch[CHILD_STDIN]->compress = true;

    ch[CHILD_STDIN]->track_bytes_written = true;
    ch[CHILD_STDIN]->bytes_written =
        ringbuf_room(ch[CHILD_STDIN]->rb);

    ch[CHILD_STDOUT] = channel_new(child->fd[1],
                                   shex_hello->si[1].bufsz,
                                   CHANNEL_FROM_FD);
    ch[CHILD_STDOUT]->track_window = true;

    if (shex_hello->si[1].compress)
        ch[CHILD_STDOUT]->compress = true;

    ch[CHILD_STDERR] = channel_new(child->fd[2],
                                   shex_hello->si[2].bufsz,
                                   CHANNEL_FROM_FD);
    ch[CHILD_STDERR]->track_window = true;

    if (shex_hello->si[2].compress)
        ch[CHILD_STDERR]->compress = true;

    sh->ch = ch;
    io_loop_init(sh);

    PUMP_WHILE(sh, (!channel_dead_p(ch[FROM_PEER]) &&
                    !channel_dead_p(ch[TO_PEER]) &&
                    (!channel_dead_p(ch[CHILD_STDOUT]) ||
                     !channel_dead_p(ch[CHILD_STDERR]))));

    if (channel_dead_p(ch[FROM_PEER]) || channel_dead_p(ch[TO_PEER])) {
        dbg("abnormal exit: closing peer channels");

        //
        // If we lost our peer connection, make sure the child sees
        // SIGHUP instead of seeing its stdin close: just drain any
        // internally-buffered IO and exit.  When we lose the pty, the
        // child gets SIGHUP.
        //

        // Make sure we won't be getting any more commands.

        channel_close(ch[FROM_PEER]);
        channel_close(ch[TO_PEER]);

        dbg("waiting for peer channels to die");

        PUMP_WHILE(sh, (!channel_dead_p(ch[FROM_PEER]) ||
                        !channel_dead_p(ch[TO_PEER])));

        // Drain output buffers
        dbg("closing child stdin");
        channel_close(ch[CHILD_STDIN]);
        dbg("waiting for child stdin to close");
        PUMP_WHILE(sh, !channel_dead_p(ch[CHILD_STDIN]));
        dbg("exiting");
        return 128 + SIGHUP;
    }

    //
    // Clean exit: close standard handles and drain IO.  Peer still
    // has no idea that we're exiting.  Get exit status, send that to
    // peer, then wait for peer to shut down our connection.  N.B.
    // it's important to wait for FROM_PEER to die after we close
    // TO_PEER; ADB sometimes drops the last few bytes from a
    // connection if we exit immediately after write, and waiting for
    // our peer to close the control connection indicates that it's
    // acknowledged receipt of our close-status message.
    //

    dbg("clean exit");

    channel_close(ch[CHILD_STDIN]);
    channel_close(ch[CHILD_STDOUT]);
    channel_close(ch[CHILD_STDERR]);

    PUMP_WHILE (sh, (!channel_dead_p(ch[CHILD_STDIN]) ||
                     !channel_dead_p(ch[CHILD_STDOUT]) ||
                     !channel_dead_p(ch[CHILD_STDERR])));

    send_exit_message(child_wait(child), sh);
    channel_close(ch[TO_PEER]);

    PUMP_WHILE(sh, !channel_dead_p(ch[TO_PEER]));
    PUMP_WHILE(sh, !channel_dead_p(ch[FROM_PEER]));
    return 0;
}

static void
stub_main_trampoline(void* data)
{
    struct main_args* ma = data;
    ma->result = stub_main_1(ma->argc, ma->argv);
}

static void
send_error_packet(void* data)
{
    struct errinfo* ei = data;
    size_t msg_length = strlen(ei->msg);
    struct msg_error* me;
    size_t packet_length = XMIN(msg_length + sizeof (*me), MSG_MAX_SIZE);
    msg_length = packet_length - sizeof (*me);
    me = alloca(packet_length);
    memset(me, 0, sizeof (*me));
    me->msg.type = MSG_ERROR;
    me->msg.size = packet_length;
    memcpy(&me->text[0], ei->msg, msg_length);
    write_all(1, me, packet_length);
}

int
stub_main(int argc, const char** argv)
{
    if (argc != 1)
        die(EINVAL, "this command is internal");

    struct main_args ma = { .argc = argc, .argv = argv };
    struct errinfo ei = { .want_msg = true };
    if (catch_error(stub_main_trampoline, &ma, &ei)) {
#ifdef __ANDROID__
        (void) __android_log_print(
            ANDROID_LOG_ERROR,
            LOG_TAG,
            "%s: %s",
            ei.prgname, ei.msg);
#endif

        if (should_send_error_packet) {
            (void) catch_error(send_error_packet, &ei, NULL);
            return 1; // Exit silently
        }

        die(ei.err, "%s", ei.msg);
    }

    return ma.result;
}
