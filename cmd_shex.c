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
#include <getopt.h>
#include <ctype.h>
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
#include "argv.h"
#include "strutil.h"
#include "cmd_shex.h"

enum shex_mode {
    SHEX_MODE_SHELL,
    SHEX_MODE_RCMD,
};

static const char shex_usage[] = (
    "\n"
    "  -t\n"
    "  --force-tty\n"
    "    Allocate a PTY even when CMD is given\n"
    "\n"
    "  -E EXENAME\n"
    "  --exename EXENAME\n"
    "    Run EXENAME on remote host.  Default is CMD, which becomes\n"
    "    argv[0] in any case.\n"
    "\n"
    "  -T\n"
    "  --disable-tty\n"
    "    Never give the remote command a pseudo-terminal.\n"
    "\n"
    "  -r\n"
    "  --root\n"
    "    Run remote command or shell as root.\n"
    "\n"
    "  -u USER\n"
    "  --user USER\n"
    "    Run remote command or shell as USER.\n"
    "\n"
    "  -U\n"
    "  --socket\n"
    "    Use a socketpair for child stdin and stdout.\n"
    "\n"
    "  -D\n"
    "  --no-ctty\n"
    "    Run child without a controlling terminal.  On disconnect,\n"
    "    child will not receive SIGHUP as it normally would.\n"
    "\n"
    "  -C DIR\n"
    "  --chdir DIR\n"
    "    Change to DIR before executing child.\n"
    "\n"
    "  -h\n"
    "  --help\n"
    "    Display this message.\n"
    "\n"
    "  -d, -e, -s, -p, -H, -P\n"
    "    Control the device to which fb-adb connects.  See adb help.\n"
    "\n"
    );

static void
print_usage(enum shex_mode smode)
{
    if (smode == SHEX_MODE_SHELL)
        printf("%s [OPTS] [CMD [ARGS...]]: "
               "run shell command on Android device\n",
               prgname);
    else
        printf("%s [OPTS] PROGRAM [ARGS...]: "
               "run program on Android device; bypass shell\n",
               prgname);

    fputs(shex_usage, stdout);
}

struct fb_adb_shex {
    struct fb_adb_sh sh;
    int child_exit_status;
    bool child_exited;
};

static struct child*
start_stub_local(void)
{
    const struct child_start_info csi = {
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

static void
send_stub(const void* data,
          size_t datasz,
          const char* const* adb_args,
          const char* adb_name)
{
    SCOPED_RESLIST(rl);
    const char* tmpfilename;
    FILE* tmpfile = xnamed_tempfile(&tmpfilename);
    if (fwrite(data, datasz, 1, tmpfile) != 1)
        die_errno("fwrite");
    if (fflush(tmpfile) == -1)
        die_errno("fflush");
    // N.B. The device-side adb server helpfully copies the user
    // permission bits to group and world, so if we were to make this
    // file writable for us locally, we'd actually be making it
    // world-writable on device!
    if (fchmod(fileno(tmpfile), 0555 /* -r-xr-xr-x */) == -1)
        die_errno("fchmod");
    adb_send_file(tmpfilename, adb_name, adb_args);
}

static struct child*
try_adb_stub(const struct child_start_info* csi,
             const char* adb_name,
             int* uid,
             char** err)
{
    struct reslist* rl_stub = reslist_push_new();
    struct child* child = child_start(csi);
    SCOPED_RESLIST(rl_local);
    struct chat* cc = chat_new(child->fd[0]->fd, child->fd[1]->fd);
    chat_swallow_prompt(cc);

    *err = NULL;

    // We choose adb_name such that it doesn't need to be quoted
    char* cmd = NULL;

#ifndef NDEBUG
    const char* remote_debug = getenv("FB_ADB_REMOTE_DEBUG");
    if (remote_debug)
        cmd = xaprintf("FB_ADB_DEBUG='%s' exec %s stub",
                       remote_debug,
                       adb_name);
#endif

    if (cmd == NULL)
        cmd = xaprintf("exec %s stub", adb_name);

    dbg("cmd for stub: [%s]", cmd);

    unsigned promptw = 40;
    if (strlen(cmd) > promptw) {
        // The extra round trip sucks, but if we don't do this, mksh's
        // helpful line editing will screw up our echo detection.
        unsigned long total_promptw = promptw + strlen(cmd);
        chat_talk_at(cc, xaprintf("COLUMNS=%lu", total_promptw));
        chat_swallow_prompt(cc);
    }

    chat_talk_at(cc, cmd);
    char* resp = chat_read_line(cc);
    dbg("stub resp: [%s]", resp);
    int n = -1;
    uintmax_t ver;
    sscanf(resp, FB_ADB_PROTO_START_LINE "%n", &ver, uid, &n);
    if (n != -1 && build_time <= ver) {
        reslist_pop_nodestroy(rl_stub);
        return child;
    }

    reslist_pop_nodestroy(rl_stub);
    child_kill(child, SIGTERM);
    (void) child_wait(child);
    *err = xstrdup(resp);
    reslist_destroy(rl_stub);
    return NULL;
}

struct delete_device_tmpfile {
    const char** adb_args;
    char* device_filename;
};

static void
delete_device_tmpfile_cleanup_1(void* data)
{
    struct delete_device_tmpfile* ddt = data;
    const struct child_start_info csi = {
        .flags = CHILD_NULL_STDIN | CHILD_NULL_STDOUT | CHILD_NULL_STDERR,
        .exename = "adb",
        .argv = argv_concat((const char*[]){"adb", NULL},
                            ddt->adb_args,
                            (const char*[]){"shell",
                                    "rm",
                                    "-f",
                                    // Chosen not to require quoting
                                    ddt->device_filename,
                                    NULL}),
    };

    child_wait(child_start(&csi));
}

__attribute__((unused))
static void
delete_device_tmpfile_cleanup(void* data)
{
    SCOPED_RESLIST(rl_cleanup);
    (void) catch_error(delete_device_tmpfile_cleanup_1, data, NULL);
}

static void
add_cleanup_delete_device_tmpfile(const char* device_filename,
                                  const char* const* adb_args)
{
    struct cleanup* cl = cleanup_allocate();
    struct delete_device_tmpfile* ddt = xcalloc(sizeof (*ddt));
    ddt->device_filename = xstrdup(device_filename);
    ddt->adb_args = argv_concat_deepcopy(adb_args, NULL);
    cleanup_commit(cl, delete_device_tmpfile_cleanup, ddt);
}

static struct child*
start_stub_adb(bool force_send_stub,
               const char* const* adb_args,
               int* uid)
{
    const struct child_start_info csi = {
        .flags = CHILD_INHERIT_STDERR,
        .exename = "adb",
        .argv = argv_concat((const char*[]){"adb", NULL},
                            adb_args,
                            (const char*[]){"shell", NULL},
                            NULL)
    };

    struct child* child = NULL;
    char* err = NULL;
    if (!force_send_stub)
        child = try_adb_stub(&csi, FB_ADB_REMOTE_FILENAME, uid, &err);

    if (child == NULL) {
        static const size_t random_suffix_bytes = 10;
        char* tmp_adb = xaprintf(
            "%s.%s",
            FB_ADB_REMOTE_FILENAME,
            hex_encode_bytes(
                generate_random_bytes(random_suffix_bytes),
                random_suffix_bytes));

        add_cleanup_delete_device_tmpfile(tmp_adb, adb_args);

        size_t ns = nr_stubs;
        for (unsigned i = 0; i < ns && !child; ++i) {
            send_stub(stubs[i].data, stubs[i].size, adb_args, tmp_adb);
            child = try_adb_stub(&csi, tmp_adb, uid, &err);
        }

        if (!child)
            die(ECOMM, "trouble starting adb stub: %s", err);

        child_kill(child, SIGTERM);
        child_wait(child);
        adb_rename_file(tmp_adb, FB_ADB_REMOTE_FILENAME, adb_args);
        child = try_adb_stub(&csi, FB_ADB_REMOTE_FILENAME, uid, &err);
        if (!child)
            die(ECOMM, "trouble starting adb stub: %s", err);
    }

    return child;
}

static void
shex_process_msg(struct fb_adb_sh* sh, struct msg mhdr)
{
    if (mhdr.type == MSG_CHILD_EXIT) {
        struct fb_adb_shex* shex = (struct fb_adb_shex*) sh;
        struct msg_child_exit m;
        read_cmdmsg(sh, mhdr, &m, sizeof (m));
        dbgmsg(&m.msg, "recv");
        shex->child_exited = true;
        shex->child_exit_status = m.exit_status;
        return;
    }

    fb_adb_sh_process_msg(sh, mhdr);
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

struct tty_flags {
    unsigned tty_p : 1;
    unsigned want_pty_p : 1;
};

struct msg_shex_hello*
make_hello_msg(size_t cmd_bufsz,
               size_t stream_bufsz,
               size_t nr_argv,
               struct tty_flags tty_flags[3])
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
        m->si[i].pty_p = tty_flags[i].want_pty_p;
    }

    m->posix_vdisable_value = _POSIX_VDISABLE;
    struct term_control* tc = &m->tctl[0];
    struct termios in_attr;
    struct termios out_attr;

    int in_tty = -1;
    if (m->si[0].pty_p && tty_flags[0].tty_p) {
        in_tty = 0;
        xtcgetattr(in_tty, &in_attr);
        m->ispeed = cfgetispeed(&in_attr);
    }

    int out_tty = -1;
    if (m->si[1].pty_p && tty_flags[1].tty_p)
        out_tty = 1;
    else if (m->si[2].pty_p && tty_flags[2].tty_p)
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

    if (totalsz <= UINT16_MAX) {
        m.type = type;
        m.size = totalsz;
        write_all_adb_encoded(fd, &m, sizeof (m));
        write_all_adb_encoded(fd, val, valsz);
    } else if (type == MSG_CMDLINE_ARGUMENT) {
        struct msg_cmdline_argument_jumbo mj;
        memset(&mj, 0, sizeof (mj));
        mj.msg.type = MSG_CMDLINE_ARGUMENT_JUMBO;
        mj.msg.size = sizeof (mj);
        mj.actual_size = valsz;
        write_all_adb_encoded(fd, &mj, sizeof (mj));
        write_all_adb_encoded(fd, val, valsz);
    } else {
        die(EINVAL, "command line argument too long");
    }
}

static void
lim_format_shell_command_line(const char *const* argv,
                              int argc,
                              size_t *pos,
                              char *buf,
                              size_t bufsz)
{
    if (argc > 0) {
        /* Special case: don't quote the first argument. */
        lim_strcat(argv[0], pos, buf, bufsz);
    }

    for (int i = 1; i < argc; ++i) {
        lim_outc(' ', pos, buf, bufsz);
        lim_shellquote(argv[i], pos, buf, bufsz);
    }
}

/* Replace a command line with a shell invocation. */
static void
make_shell_command_line(const char* shell,
                        int* argc,
                        const char*** argv)
{
    size_t sz = 0;
    lim_format_shell_command_line(*argv, *argc, &sz, NULL, 0);
    char* script = xalloc(sz + 1);
    size_t pos = 0;
    lim_format_shell_command_line(*argv, *argc, &pos, script, sz);
    script[pos] = '\0';
    *argc = 3;
    *argv = argv_concat((const char*[]) {shell, "-c", script, NULL},
                        NULL);
}

static void
send_cmdline(int fd,
             int argc,
             const char* const* argv,
             const char* exename)
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

static void
command_re_exec_as_root(struct child* child)
{
    SCOPED_RESLIST(rl_re_exec_as_root);

    // Tell child to re-exec itself as root.  It'll send another hello
    // message, which we read below.

    struct msg rmsg = {
        .size = sizeof (rmsg),
        .type = MSG_EXEC_AS_ROOT,
    };

    write_all_adb_encoded(child->fd[0]->fd, &rmsg, rmsg.size);

    struct chat* cc = chat_new(child->fd[0]->fd, child->fd[1]->fd);
    char* resp = chat_read_line(cc);
    int n = -1;
    int uid;
    uintmax_t ver;
    sscanf(resp, FB_ADB_PROTO_START_LINE "%n", &ver, &uid, &n);

    if (n == -1)
        die(ECOMM, "trouble re-execing adb stub as root: %s", resp);

    if (uid != 0)
        die(ECOMM, "told child to re-exec as root; gave us uid=%d", uid);
}

static void
command_re_exec_as_user(struct child* child, const char* username)
{
    SCOPED_RESLIST(rl_re_exec_as_root);

    // Tell child to re-exec itself as our user.  It'll send another
    // hello message, which we read below.

    struct msg_exec_as_user* m;
    size_t username_length = strlen(username);
    size_t alloc_size = sizeof (*m);
    if (SATADD(&alloc_size, alloc_size, username_length))
        die(EINVAL, "username too long");

    m = xcalloc(alloc_size);
    m->msg.size = alloc_size;
    m->msg.type = MSG_EXEC_AS_USER;
    memcpy(m->username, username, username_length);
    write_all_adb_encoded(child->fd[0]->fd, m, m->msg.size);

    struct chat* cc = chat_new(child->fd[0]->fd, child->fd[1]->fd);
    char* resp = chat_read_line(cc);
    int n = -1;
    int uid;
    uintmax_t ver;
    sscanf(resp, FB_ADB_PROTO_START_LINE "%n", &ver, &uid, &n);

    if (n == -1)
        die(ECOMM, "trouble re-execing adb stub as %s: %s",
            username, resp);
}

static void
send_chdir(int fd, const char* child_chdir)
{
    size_t dirsz;
    size_t totalsz;
    struct msg_chdir mchd;

    dirsz = strlen(child_chdir);

    if (SATADD(&totalsz, dirsz, sizeof (mchd)) || totalsz > UINT16_MAX)
        die(EINVAL, "directory too long");

    memset(&mchd, 0, sizeof (mchd));
    mchd.msg.size = totalsz;
    mchd.msg.type = MSG_CHDIR;

    dbg("sending chdir to [%s] %hu", child_chdir, mchd.msg.size);

    write_all_adb_encoded(fd, &mchd, sizeof (mchd));
    write_all_adb_encoded(fd, child_chdir, dirsz);
}

static int
shex_main_common(enum shex_mode smode, int argc, const char** argv)
{
    size_t cmd_bufsz = DEFAULT_CMD_BUFSZ;
    size_t child_stream_bufsz = DEFAULT_STREAM_BUFSZ;
    size_t our_stream_bufsz = DEFAULT_STREAM_BUFSZ;
    bool local_mode = false;
    enum { TTY_AUTO,
           TTY_SOCKPAIR,
           TTY_DISABLE,
           TTY_ENABLE,
           TTY_SUPER_ENABLE } tty_mode = TTY_AUTO;

    sigset_t orig_sigmask;
    sigset_t blocked_signals;
    const char* exename = NULL;
    bool force_send_stub = false;
    struct tty_flags tty_flags[3];
    const char* const* adb_args = empty_argv;
    bool want_root = false;
    char* want_user = NULL;
    bool want_ctty = true;
    char* child_chdir = NULL;

    memset(&tty_flags, 0, sizeof (tty_flags));
    for (int i = 0; i < 3; ++i)
        if (isatty(i)) {
            hack_reopen_tty(i);
            tty_flags[i].tty_p = true;
        }

    static struct option opts[] = {
        { "help", no_argument, NULL, 'h' },
        { "local", no_argument, NULL, 'l' },
        { "exename", required_argument, NULL, 'E' },
        { "force-send-stub", no_argument, NULL, 'f' },
        { "force-tty", no_argument, NULL, 't' },
        { "disable-tty", no_argument, NULL, 'T' },
        { "no-ctty", no_argument, NULL, 'D' },
        { "root", no_argument, NULL, 'r' },
        { "socket", no_argument, NULL, 'U' },
        { "user", required_argument, NULL, 'u' },
        { "chdir", required_argument, NULL, 'C' },
        { 0 }
    };

    for (;;) {
        int c = getopt_long(argc,
                            (char**) argv,
                            "+:lhE:ftTdes:p:H:P:rUu:DC:",
                            opts,
                            NULL);
        if (c == -1)
            break;

        switch (c) {
            case 'r':
                if (want_user != NULL)
                    die(EINVAL, "cannot both run-as user and su to root");
                want_root = true;
                break;
            case 'E':
                exename = optarg;
                break;
            case 'f':
                force_send_stub = true;
                break;
            case 'l':
                local_mode = true;
                break;
            case 't':
                if (tty_mode == TTY_ENABLE)
                    tty_mode = TTY_SUPER_ENABLE;
                else
                    tty_mode = TTY_ENABLE;
                break;
            case 'T':
                tty_mode = TTY_DISABLE;
                break;
            case 'd':
            case 'e':
                adb_args = argv_concat(
                    adb_args,
                    (const char*[]){xaprintf("-%c", c), NULL},
                    NULL);
                break;
            case 's':
            case 'p':
            case 'H':
            case 'P':
                adb_args = argv_concat(
                    adb_args,
                    (const char*[]){xaprintf("-%c", c),
                                    xstrdup(optarg),
                                    NULL},
                    NULL);
                break;
            case 'U':
                tty_mode = TTY_SOCKPAIR;
                break;
            case 'u':
                if (want_root)
                    die(EINVAL, "cannot both run-as user and su to root");
                want_user = xstrdup(optarg);
                break;
            case 'D':
                want_ctty = false;
                break;
            case 'C':
                child_chdir = xstrdup(optarg);
                break;
            case ':':
                if (optopt == '\0') {
                    die(EINVAL, "missing argument for %s", argv[optind-1]);
                } else {
                    die(EINVAL, "missing argument for -%c", optopt);
                }
            case '?':
                if (optopt == '?') {
                    // Fall through to help
                } else if (optopt == '\0') {
                    die(EINVAL, "invalid option %s", argv[optind-1]);
                } else {
                    die(EINVAL, "invalid option -%d", (int) optopt);
                }
            case 'h':
                print_usage(smode);
                return 0;
            default:
                abort();
        }
    }

    argc -= optind;
    argv += optind;

    if (smode == SHEX_MODE_RCMD && argc == 0)
        die(EINVAL, "remote command not given");

    if (smode == SHEX_MODE_SHELL && argc > 0)
        make_shell_command_line("sh", &argc, &argv);

    if (tty_mode == TTY_AUTO)
        tty_mode = (argc == 0) ? TTY_ENABLE : TTY_DISABLE;

    for (int i = 0; i < 3; ++i)
        if ((tty_mode == TTY_ENABLE && tty_flags[i].tty_p)
            || tty_mode == TTY_SUPER_ENABLE)
        {
            tty_flags[i].want_pty_p = true;
        }

    sigemptyset(&blocked_signals);
    sigaddset(&blocked_signals, SIGWINCH);
    sigprocmask(SIG_BLOCK, &blocked_signals, &orig_sigmask);
    signal(SIGWINCH, handle_sigwinch);

    size_t args_to_send = XMAX((size_t) argc + 1, 2);
    struct msg_shex_hello* hello_msg =
        make_hello_msg(cmd_bufsz,
                       child_stream_bufsz,
                       args_to_send,
                       tty_flags);

    if (tty_mode == TTY_SOCKPAIR) {
        hello_msg->stdio_socket_p = 1;
    }

    if (want_ctty)
        hello_msg->ctty_p = 1;

    struct child* child;
    int uid;
    if (local_mode) {
        if (want_root)
            die(EINVAL, "root upgrade not supported in local mode");
        child = start_stub_local();
    } else {
        child = start_stub_adb(force_send_stub, adb_args, &uid);
    }

    if (want_root && uid != 0)
        command_re_exec_as_root(child);

    if (want_user)
        command_re_exec_as_user(child, want_user);

    write_all_adb_encoded(child->fd[0]->fd, hello_msg, hello_msg->msg.size);

    if (child_chdir)
        send_chdir(child->fd[0]->fd, child_chdir);

    send_cmdline(child->fd[0]->fd, argc, argv, exename);

    struct fb_adb_shex shex;
    memset(&shex, 0, sizeof (shex));
    struct fb_adb_sh* sh = &shex.sh;

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
        if (tty_flags[i].tty_p && tty_flags[i].want_pty_p)
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

int
shex_main(int argc, const char** argv)
{
    return shex_main_common(SHEX_MODE_SHELL, argc, argv);
}

int
shex_main_rcmd(int argc, const char** argv)
{
    return shex_main_common(SHEX_MODE_RCMD, argc, argv);
}

static const struct option*
find_option_by_name(const struct option* options, const char* name)
{
    while (options->name) {
        if (!strcmp(options->name, name)) {
            return options;
        }

        options++;
    }

    return NULL;
}

int
shex_wrapper(const char* wrapped_cmd,
             const char* opts,
             const struct option* longopts,
             const char* usage,
             const char** argv)
{
    const char* argv0 = argv[0];
    const char* const* rcmd_args = empty_argv;
    const char* const* remote_args = empty_argv;
    const char* arg;
    bool posix_correct = false;
    const char* adb_opts = "des:p:H:P:";
    char c;

    if (opts != NULL) {
        while (strchr("+:", opts[0])) {
            if (opts[0] == '+')
                posix_correct = true;
            ++opts;
        }

#ifndef NDEBUG
        for (const char* p = opts; *p; ++p) {
            if (*p != ':' && strchr(adb_opts, *p)) {
                assert(!"conflicting options in shex_wrapper!");
            }
        }
#endif
    }

#define ADDARG(_dest, _arg)                                        \
    ({*(_dest) = argv_concat(*(_dest),                             \
                             (const char*[]) {(_arg), NULL},       \
                            NULL);                                 \
    })

    ADDARG(&rcmd_args, *argv++);

    // Split the argument list into arguments for rcmd and arguments
    // for the remote command.

    while ((arg = *argv++)) {
        if ((posix_correct && arg[0] != '-') ||
            (arg[0] == '-' && arg[1] == '-' && arg[2] == '\0'))
        {
            remote_args = argv_concat(remote_args, argv - 1, NULL);
            break;
        }

        if (arg[0] != '-') {
            ADDARG(&remote_args, arg);
            continue;
        }

        if (arg[1] == '-') {
            const char* longname = &arg[2];
            const char* value = NULL;

            if (strchr(longname, '=')) {
                longname = xstrdup(longname);
                char* eq = strchr(longname, '=');
                *eq++ = '\0';
                value = eq;
            }

            if (!strcmp(longname, "help")) {
                fputs(usage, stdout);
                return 0;
            }

            const struct option* longopt =
                ( longopts
                  ? find_option_by_name(longopts, longname)
                  : NULL );

            if (longopt == NULL)
                die(EINVAL, "invalid option --%s", longname);

            if (value && !longopt->has_arg) {
                die(EINVAL,
                    "option --%s does not accept an argument",
                    longname);

            }

            if (longopt->has_arg == 1 && !value) {
                value = *argv++;
                if (!value) {
                    die(EINVAL,
                        "no argument for option %s",
                        longname);
                }
            }

            ADDARG(&remote_args,
                   ((value != NULL)
                    ? xaprintf("--%s=%s", longname, value)
                    : longname));

            continue;
        }

        ++arg;
        while ((c = *arg++)) {
            bool rcmd = false;
            const char* ap = NULL;

            if (c == 'h' || c == '?') {
                fputs(usage, stdout);
                return 0;
            }

            if ((ap = strchr(adb_opts, c)))
                rcmd = true;

            if (!ap && opts)
                ap = strchr(opts, c);

            if (!ap)
                die(EINVAL, "invalid option -%c", c);

            bool has_arg = (ap[1] == ':');
            const char* value = NULL;

            if (has_arg && *arg) {
                value = arg;
                arg += strlen(value);
            } else if (has_arg) {
                value = *argv++;
                if (!value)
                    die(EINVAL, "no argument for option -%c", c);
            }

            ADDARG((rcmd ? &rcmd_args : &remote_args),
                   xaprintf("-%c%s", c, value ?: ""));
        }
    }

    const char* invoke_self_args[] = {
        "-E/proc/self/exe",
        argv0,
        wrapped_cmd,
        NULL
    };

    const char** nargv =
        argv_concat(rcmd_args,
                    invoke_self_args,
                    remote_args,
                    NULL);

    return shex_main_common(SHEX_MODE_RCMD,
                            argv_count(nargv),
                            nargv);

#undef ADDARG
}
