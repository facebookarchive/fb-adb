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
#include <sys/socket.h>
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
#include "net.h"

enum shex_mode {
    SHEX_MODE_SHELL,
    SHEX_MODE_RCMD,
};

enum transport {
    transport_shell,
    transport_unix,
    transport_tcp,
};

struct childcom {
    struct fdh* to_child;
    struct fdh* from_child;
    void (*writer)(int, const void*, size_t);
};

static void
tc_write(const struct childcom* tc,
         const void* buf,
         size_t sz)
{
    tc->writer(tc->to_child->fd, buf, sz);
}

static void
tc_sendmsg(const struct childcom* tc,
           const struct msg* m)
{
    dbgmsg(m, "tc_sendmsg");
    tc_write(tc, m, m->size);
}

static struct msg*
tc_recvmsg(const struct childcom* tc)
{
    return read_msg(tc->from_child->fd, read_all);
}

static struct chat*
tc_chat_new(const struct childcom* tc)
{
    return chat_new(tc->to_child->fd, tc->from_child->fd);
}

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

    static const char usage_body[] = {
#include "cmd_shex_usage.inc"
    };

    fputc('\n', stdout);
    fwrite(usage_body, sizeof (usage_body), 1, stdout);
}

struct child_hello {
    uintmax_t ver;
    int uid;
    unsigned api_level;
};

struct fb_adb_shex {
    struct fb_adb_sh sh;
    int child_exit_status;
    bool child_exited;
};

static bool
parse_child_hello(const char* line, struct child_hello* chello)
{
    memset(chello, 0, sizeof (*chello));
    int n = -1;
    sscanf(line, FB_ADB_PROTO_START_LINE "%n",
           &chello->ver,
           &chello->uid,
           &chello->api_level,
           &n);

    return n != -1;
}

static struct child*
start_stub_local(void)
{
    const struct child_start_info csi = {
        .flags = CHILD_INHERIT_STDERR,
        .exename = orig_argv0,
        .argv = ARGV(orig_argv0, "stub"),
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
             struct child_hello* chello,
             char** err)
{
    SCOPED_RESLIST(rl);
    struct child* child = child_start(csi);
    struct chat* cc = chat_new(child->fd[0]->fd, child->fd[1]->fd);
    chat_swallow_prompt(cc);

    *err = NULL;

    // We choose adb_name such that it doesn't need to be quoted
    char* cmd = NULL;

#ifndef NDEBUG
    const char* remote_wrapper = getenv("FB_ADB_REMOTE_WRAPPER");
    if (remote_wrapper)
        adb_name = xaprintf("%s %s", remote_wrapper, adb_name);

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

    if (parse_child_hello(resp, chello) && chello->ver == build_time) {
        dbg("found good child version");
        reslist_xfer(rl->parent, rl);
        return child;
    }

    child_kill(child, SIGTERM);
    (void) child_wait(child);

    WITH_CURRENT_RESLIST(rl->parent);
    *err = xstrdup(resp);
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
        .argv = ARGV_CONCAT(ARGV("adb"),
                            ddt->adb_args,
                            ARGV("shell",
                                 "</dev/null",
                                 "rm",
                                 "-f",
                                 // Chosen not to require quoting
                                 ddt->device_filename)),
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
               struct child_hello* chello)
{
    const struct child_start_info csi = {
        .flags = CHILD_INHERIT_STDERR,
        .exename = "adb",
        .argv = ARGV_CONCAT(ARGV("adb"), adb_args, ARGV("shell")),
    };

    struct child* child = NULL;
    char* err = NULL;
    if (!force_send_stub)
        child = try_adb_stub(&csi, FB_ADB_REMOTE_FILENAME, chello, &err);

    if (child == NULL) {
        char* tmp_adb = xaprintf(
            "%s.%s",
            FB_ADB_REMOTE_FILENAME,
            gen_hex_random(10));

        add_cleanup_delete_device_tmpfile(tmp_adb, adb_args);

        size_t ns = nr_stubs;
        for (unsigned i = 0; i < ns && !child; ++i) {
            send_stub(stubs[i].data, stubs[i].size, adb_args, tmp_adb);
            child = try_adb_stub(&csi, tmp_adb, chello, &err);
        }

        if (!child)
            die(ECOMM, "trouble starting adb stub: %s", err);

        child_kill(child, SIGTERM);
        child_wait(child);
        unsigned api_level = adb_api_level(adb_args);
        dbg("device appears to have API level %u", api_level);
        adb_rename_file(tmp_adb,
                        FB_ADB_REMOTE_FILENAME,
                        api_level,
                        adb_args);
        child = try_adb_stub(&csi, FB_ADB_REMOTE_FILENAME, chello, &err);
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
    unsigned compress : 1;
};

struct msg_shex_hello*
make_hello_msg(size_t max_cmdsz,
               size_t stdio_ringbufsz,
               size_t command_ringbufsz,
               size_t nr_argv,
               struct tty_flags tty_flags[3])
{
    struct msg_shex_hello* m;
    size_t sz = sizeof (*m) + nr_termbits * sizeof (m->tctl[0]);
    m = xcalloc(sz);
    m->msg.type = MSG_SHEX_HELLO;
    m->version = build_time;
    m->nr_argv = nr_argv;
    m->maxmsg = XMIN(max_cmdsz, MSG_MAX_SIZE);
    m->stub_send_bufsz = command_ringbufsz;
    m->stub_recv_bufsz = command_ringbufsz;
    for (int i = 0; i < 3; ++i) {
        m->si[i].bufsz = stdio_ringbufsz;
        m->si[i].pty_p = tty_flags[i].want_pty_p;
        m->si[i].compress = tty_flags[i].compress;
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

struct environ_op {
    struct environ_op* next;
    const char* name;
    const char* value;
};

static struct environ_op*
reverse_environ_ops(struct environ_op* environ_ops)
{
    // Reverse the operations list to restore argv order
    struct environ_op* new_environ_ops = NULL;
    while (environ_ops != NULL) {
        struct environ_op* eop = environ_ops;
        environ_ops = environ_ops->next;
        eop->next = new_environ_ops;
        new_environ_ops = eop;
    }

    return new_environ_ops;
}

static void
send_environ_set(const struct childcom* tc,
                 const char* name,
                 const char* value)
{
    size_t name_length = strlen(name);
    size_t value_length = strlen(value);
    struct msg_environment_variable_set* e;
    size_t msglen = sizeof (*e) + name_length + 1 + value_length;
    if (msglen <= MSG_MAX_SIZE) {
        e = alloca(msglen);
        memset(e, 0, sizeof (*e));
        e->msg.type = MSG_ENVIRONMENT_VARIABLE_SET;
        e->msg.size = msglen;
        memcpy(&e->value[0], name, name_length);
        e->value[name_length] = '\0';
        memcpy(&e->value[name_length+1], value, value_length);
        tc_sendmsg(tc, &e->msg);
    } else {
        if (name_length > UINT32_MAX || value_length > UINT32_MAX)
            die(EINVAL, "environment variable too long");

        struct msg_environment_variable_set_jumbo ej;
        memset(&ej, 0, sizeof (ej));
        ej.msg.type = MSG_ENVIRONMENT_VARIABLE_SET_JUMBO;
        ej.msg.size = sizeof (ej);
        ej.name_length = name_length;
        ej.value_length = value_length;
        tc_sendmsg(tc, &ej.msg);
        tc_write(tc, name, name_length);
        tc_write(tc, value, value_length);
    }
}

static void
send_environ_unset(const struct childcom* tc,
                   const char* name)
{
    size_t name_length = strlen(name);
    struct msg_environment_variable_unset* ue;
    size_t msglen = sizeof (*ue) + name_length;
    if (msglen <= MSG_MAX_SIZE) {
        ue = alloca(msglen);
        memset(ue, 0, sizeof (*ue));
        ue->msg.type = MSG_ENVIRONMENT_VARIABLE_UNSET;
        ue->msg.size = msglen;
        memcpy(&ue->name, name, name_length);
        tc_sendmsg(tc, &ue->msg);
    } else {
        if (name_length > UINT32_MAX)
            die(EINVAL, "environment variable too long");

        struct msg_environment_variable_unset_jumbo uej;
        memset(&uej, 0, sizeof (uej));
        uej.msg.type = MSG_ENVIRONMENT_VARIABLE_UNSET_JUMBO;
        uej.msg.size = sizeof (uej);
        uej.name_length = name_length;
        tc_sendmsg(tc, &uej.msg);
        tc_write(tc, name, name_length);
    }
}

static void
send_environ_clearenv(const struct childcom* tc)
{
    struct msg cev;
    memset(&cev, 0, sizeof (cev));
    cev.type = MSG_CLEARENV;
    cev.size = sizeof (cev);
    tc_sendmsg(tc, &cev);
}

static void
send_environ_ops(const struct childcom* tc,
                 struct environ_op* environ_ops)
{
    while (environ_ops != NULL) {
        struct environ_op* eop = environ_ops;
        environ_ops = environ_ops->next;
        if (eop->name && eop->value)
            send_environ_set(tc, eop->name, eop->value);
        else if (eop->name)
            send_environ_unset(tc, eop->name);
        else
            send_environ_clearenv(tc);
    }
}

static void
send_cmdline_argument(const struct childcom* tc,
                      unsigned type,
                      const void* val,
                      size_t valsz)
{
    struct msg m;
    size_t totalsz;

    if (SATADD(&totalsz, sizeof (m), valsz) || totalsz > UINT32_MAX)
        die(EINVAL, "command line argument too long");

    if (totalsz <= MSG_MAX_SIZE) {
        m.type = type;
        m.size = totalsz;
        tc_write(tc, &m, sizeof (m));
        tc_write(tc, val, valsz);
    } else if (type == MSG_CMDLINE_ARGUMENT) {
        struct msg_cmdline_argument_jumbo mj;
        memset(&mj, 0, sizeof (mj));
        mj.msg.type = MSG_CMDLINE_ARGUMENT_JUMBO;
        mj.msg.size = sizeof (mj);
        mj.actual_size = valsz;
        tc_write(tc, &mj, sizeof (mj));
        tc_write(tc, val, valsz);
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
    *argv = ARGV_CONCAT(ARGV(shell, "-c", script));
}

static void
send_cmdline(const struct childcom* tc,
             int argc,
             const char* const* argv,
             const char* exename)
{
    if (argc == 0) {
        /* Default interactive shell */
        if (exename == NULL)
            send_cmdline_argument(tc, MSG_CMDLINE_DEFAULT_SH, NULL, 0);
        else
            send_cmdline_argument(tc, MSG_CMDLINE_ARGUMENT,
                                  exename, strlen(exename));

        send_cmdline_argument(tc, MSG_CMDLINE_DEFAULT_SH_LOGIN, NULL, 0);
    } else {
        if (exename == NULL)
            exename = argv[0];

        send_cmdline_argument(tc, MSG_CMDLINE_ARGUMENT,
                              exename, strlen(exename));

        for (int i = 0; i < argc; ++i)
            send_cmdline_argument(tc, MSG_CMDLINE_ARGUMENT,
                                  argv[i], strlen(argv[i]));
    }
}

static bool
clowny_samsung_debug_output_p(const char* line)
{
    return
        string_starts_with_p(line, "Function: selinux_compare_spd_ram ,") ||
        string_starts_with_p(line, "[DEBUG] ");
}

static void
command_re_exec_as_root(const struct childcom* tc)
{
    SCOPED_RESLIST(rl);

    // Tell child to re-exec itself as root.  It'll send another hello
    // message, which we read below.

    struct msg rmsg = {
        .size = sizeof (rmsg),
        .type = MSG_EXEC_AS_ROOT,
    };

    tc_sendmsg(tc, &rmsg);

    struct chat* cc = tc_chat_new(tc);
    char* resp;

    do {
        resp = chat_read_line(cc);
    } while (clowny_samsung_debug_output_p(resp));

    struct child_hello chello;
    if (!parse_child_hello(resp, &chello))
        die(ECOMM, "trouble re-execing adb stub as root: %s", resp);

    if (chello.uid != 0)
        die(ECOMM, "told child to re-exec as root; gave us uid=%d",
            chello.uid);
}

enum re_exec_status {
    RE_EXEC_OKAY,
    RE_EXEC_STUB_NEEDED
};

struct re_exec_info {
    const struct childcom* tc;
    const char* username;
    bool shell_thunk;
};

static void
command_re_exec_as_user_1(void* arg)
{
    const struct re_exec_info* info = arg;

    SCOPED_RESLIST(rl_re_exec_as_user);

    // Tell child to re-exec itself as our user.  It'll send another
    // hello message, which we read below.

    const char* username = info->username;
    const struct childcom* tc = info->tc;

    struct msg_exec_as_user* m;
    size_t username_length = strlen(username);
    size_t alloc_size = sizeof (*m);
    if (SATADD(&alloc_size, alloc_size, username_length) ||
        alloc_size > MSG_MAX_SIZE)
    {
        die(EINVAL, "username too long");
    }

    m = xcalloc(alloc_size);
    m->msg.size = alloc_size;
    m->msg.type = MSG_EXEC_AS_USER;
    m->shell_thunk = info->shell_thunk;
    memcpy(m->username, username, username_length);
    tc_sendmsg(tc, &m->msg);

    struct chat* cc = tc_chat_new(tc);
    char* resp;

    do {
        resp = chat_read_line(cc);
    } while (clowny_samsung_debug_output_p(resp));

    struct child_hello chello;
    if (!parse_child_hello(resp, &chello))
        die(ECOMM, "trouble re-execing adb stub as %s: %s", username, resp);
}

static enum re_exec_status
command_re_exec_as_user(
    const struct childcom* tc,
    const char* username,
    bool shell_thunk)
{
    struct re_exec_info info = {
        .tc = tc,
        .username = username,
        .shell_thunk = shell_thunk,
    };

    struct errinfo ei = {
        .want_msg = 1,
    };

    if (catch_error(command_re_exec_as_user_1, &info, &ei)) {
        if (ei.err == ECOMM &&
            string_starts_with_p(ei.msg, "trouble re-execing adb stub as ") &&
            string_ends_with_p(ei.msg, "Error:Permission denied") &&
            shell_thunk == false)
        {
            dbg("error indicating retry with stub hack needed: [%s]",
                ei.msg);
            return RE_EXEC_STUB_NEEDED;
        }

        die(ei.err, "%s", ei.msg);
    }

    return RE_EXEC_OKAY;
}

static void
send_chdir(const struct childcom* tc,
           const char* child_chdir)
{
    size_t dirsz;
    size_t totalsz;
    struct msg_chdir mchd;

    dirsz = strlen(child_chdir);

    if (SATADD(&totalsz, dirsz, sizeof (mchd))
        || totalsz > MSG_MAX_SIZE)
    {
        die(EINVAL, "directory too long");
    }

    memset(&mchd, 0, sizeof (mchd));
    mchd.msg.size = totalsz;
    mchd.msg.type = MSG_CHDIR;

    dbg("sending chdir to [%s] %hu", child_chdir, mchd.msg.size);

    tc_write(tc, &mchd, sizeof (mchd));
    tc_write(tc, child_chdir, dirsz);
}

static void
send_rebind_to_unix_socket_message(const struct childcom* tc,
                                   const char* device_socket)
{
    size_t device_socket_length = strlen(device_socket);
    size_t msgsz;
    struct msg_rebind_to_unix_socket rm;

    if (SATADD(&msgsz, sizeof (rm), device_socket_length) ||
        msgsz > MSG_MAX_SIZE)
    {
        die(ERANGE, "socket name too long");
    }

    memset(&rm, 0, sizeof (rm));
    rm.msg.type = MSG_REBIND_TO_UNIX_SOCKET;
    rm.msg.size = msgsz;
    tc_write(tc, &rm.msg, sizeof (rm));
    tc_write(tc, device_socket, device_socket_length);
}

static struct childcom*
reconnect_over_unix_socket(
    const struct childcom* tc,
    const char* const* adb_args)
{
    SCOPED_RESLIST(rl);

    // N.B. We can't use reverse forwarding (having the stub connect
    // to us) because Gingerbread doesn't support reverse forwarding.
    // We need to wait for a reply from the child to ensure that we
    // don't race against the stub's call to listen().

    char* device_socket =
        xaprintf("%s/fb-adb-conn-%s.sock",
                 DEVICE_TEMP_DIR,
                 gen_hex_random(10));

    send_rebind_to_unix_socket_message(tc, device_socket);

    struct msg* reply = tc_recvmsg(tc);
    if (reply->type != MSG_LISTENING_ON_SOCKET)
        die(ECOMM, "child sent incorrect reply %u to socket bind",
            (unsigned) reply->type);

    char* host_socket =
        xaprintf("%s/fb-adb-conn-%s.sock",
                 (char*) first_non_null(
                     getenv("TEMP"),
                     getenv("TMP"),
                     getenv("TMPDIR"),
                     DEFAULT_TEMP_DIR),
                 gen_hex_random(10));

    char* remote = xaprintf("localabstract:%s", device_socket);
    char* local = xaprintf("localfilesystem:%s", host_socket);

    struct unlink_cleanup* ucl = unlink_cleanup_allocate(host_socket);
    struct remove_forward_cleanup* crf =
        remove_forward_cleanup_allocate(local, adb_args);

    adb_add_forward(local, remote, adb_args);
    unlink_cleanup_commit(ucl);
    remove_forward_cleanup_commit(crf);

    int scon = xsocket(AF_UNIX, SOCK_STREAM, 0);
    xconnect(scon, make_addr_unix_filesystem(host_socket));

    WITH_CURRENT_RESLIST(rl->parent);
    struct childcom* ntc = xcalloc(sizeof (*ntc));
    ntc->from_child = fdh_dup(scon);
    ntc->to_child = fdh_dup(scon);
    ntc->writer = write_all;
    dbg("rebound stub connection local:%s remote:%s", local, remote);
    return ntc;
}

static struct child* monitored_child;

static void
accept_die_on_sigchld_sigchld_action(
    int signo,
    siginfo_t* info,
    void* context)
{
    assert(signo == SIGCHLD);

    if (child_poll_death(monitored_child)) {
        pid_t pid = monitored_child->pid;
        monitored_child = NULL;
        die(ECOMM, "child %d died", (int) pid);
    }
}

static int
accept_die_on_sigchld(int sock, struct child* child)
{
    SCOPED_RESLIST(rl);

    if (monitored_child != NULL)
        die(EINVAL, "only one monitored child supported");

    sigset_t all_signals;
    sigfillset(&all_signals);

    struct sigaction sa = {
        .sa_sigaction = accept_die_on_sigchld_sigchld_action,
        .sa_flags = SA_SIGINFO,
    };

    memcpy(&sa.sa_mask, &all_signals, sizeof (sigset_t));

    sigaction_restore_as_cleanup(SIGCHLD, &sa);
    save_signals_unblock_for_io();
    sigaddset(&signals_unblock_for_io, SIGCHLD);
    monitored_child = child;

    sigset_t pending;
    sigpending(&pending);

    WITH_CURRENT_RESLIST(rl->parent);
    int conn = xaccept(sock);
    monitored_child = NULL;
    return conn;
}

static struct childcom*
reconnect_over_tcp_socket(const struct childcom* tc,
                          struct child* adb,
                          const char* tcp_addr)
{
    SCOPED_RESLIST(rl);

    static const struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_flags = AI_PASSIVE,
        .ai_socktype = SOCK_STREAM,
    };

    char* node;
    char* service;
    str2gaiargs(tcp_addr, &node, &service);

    struct addrinfo* ai =
        xgetaddrinfo_interruptible(node, service, &hints);

    while (ai && ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
        ai = ai->ai_next;

    if (!ai)
        die(ENOENT, "xgetaddrinfo returned no addresses");

    int sock = xsocket(ai->ai_family,
                       ai->ai_socktype,
                       ai->ai_protocol);

    int v = 1;
    xsetsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &v, sizeof (v));

    // Bind to TCP socket and start accepting connections
    xbind(sock, addrinfo2addr(ai));
    xlisten(sock, 1);

    if (ai->ai_family == AF_INET) {
        struct msg_rebind_to_tcp4_socket m;
        struct sockaddr_in* a = (struct sockaddr_in*) ai->ai_addr;
        assert(ai->ai_addrlen == sizeof (*a));
        memset(&m, 0, sizeof (m));
        m.msg.type = MSG_REBIND_TO_TCP4_SOCKET;
        m.msg.size = sizeof (m);
        m.port = a->sin_port;
        m.addr = a->sin_addr.s_addr;
        tc_sendmsg(tc, &m.msg);
    } else if (ai->ai_family == AF_INET6) {
        struct msg_rebind_to_tcp6_socket m;
        struct sockaddr_in6* a = (struct sockaddr_in6*) ai->ai_addr;
        assert(ai->ai_addrlen == sizeof (*a));
        memset(&m, 0, sizeof (m));
        m.msg.type = MSG_REBIND_TO_TCP6_SOCKET;
        m.msg.size = sizeof (m);
        m.port = a->sin6_port;
        memcpy(&m.addr, a->sin6_addr.s6_addr, 16);
        tc_sendmsg(tc, &m.msg);
    } else {
        assert(!"invalid family");
        __builtin_unreachable();
    }

    int conn = accept_die_on_sigchld(sock, adb);

    disable_tcp_nagle(conn);

    WITH_CURRENT_RESLIST(rl->parent);
    struct childcom* ntc = xcalloc(sizeof (*ntc));
    ntc->from_child = fdh_dup(conn);
    ntc->to_child = fdh_dup(conn);
    ntc->writer = write_all;
    return ntc;
}

static void
block_signal(int signo)
{
    sigset_t blocked_signals;
    sigemptyset(&blocked_signals);
    sigaddset(&blocked_signals, signo);
    sigprocmask(SIG_BLOCK, &blocked_signals, NULL);
}

static void
parse_transport(const char* s,
                enum transport* transport,
                const char** tcp_addr)
{
    if (strcmp(s, "shell") == 0) {
        *transport = transport_shell;
    } else if (strcmp(s, "socket") == 0) {
        *transport = transport_unix;
    } else if (string_starts_with_p(s, "tcp:")) {
        *transport = transport_tcp;
        const char* addrpart = s + strlen("tcp:");
        if (!strchr(addrpart, ','))
            die(EINVAL, "invalid tcp spec: no port");
        *tcp_addr = addrpart;
    } else {
        die(EINVAL, "unknown transport %s", s);
    }
}

static void
forward_envvar(struct environ_op** inout_environ_ops, const char* name)
{
    struct environ_op* environ_ops = *inout_environ_ops;
    const char* value = getenv(name);
    if (value) {
        struct environ_op* eop = xcalloc(sizeof (*eop));
        eop->next = environ_ops;
        eop->name = xstrdup(name);
        eop->value = xstrdup(value);
        environ_ops = eop;
    }

    *inout_environ_ops = environ_ops;
}

static int
shex_main_common(enum shex_mode smode, int argc, const char** argv)
{
    size_t max_cmdsz = DEFAULT_MAX_CMDSZ;
    bool local_mode = false;
    enum { TTY_AUTO,
           TTY_SOCKPAIR,
           TTY_DISABLE,
           TTY_ENABLE,
           TTY_SUPER_ENABLE } tty_mode = TTY_AUTO;

    const char* exename = NULL;
    bool force_send_stub = false;
    struct tty_flags tty_flags[3];
    const char* const* adb_args = empty_argv;
    bool want_root = false;
    char* want_user = NULL;
    bool want_ctty = true;
    char* child_chdir = NULL;
    enum transport transport = transport_shell;
    const char* tcp_addr = NULL;
    bool compress = !getenv("FB_ADB_NO_COMPRESSION");
    bool shell_thunk = false;

    const char* transport_env = getenv("FB_ADB_TRANSPORT");
    if (transport_env)
        parse_transport(transport_env, &transport, &tcp_addr);

    struct environ_op* environ_ops = NULL;

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
        { "transport", required_argument, NULL, 'X' },
        { "setenv", required_argument, NULL, 'Y' },
        { "unsetenv", required_argument, NULL, 'K' },
        { "clearenv", no_argument, NULL, 'F' },
        { 0 }
    };

    for (;;) {
        int c = getopt_long(argc,
                            (char**) argv,
                            "+:lhE:ftTdes:p:H:P:rUu:DC:X:Y:K:F",
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
                adb_args = ARGV_CONCAT(adb_args, ARGV(xaprintf("-%c", c)));
                break;
            case 's':
            case 'p':
            case 'H':
            case 'P':
                adb_args = ARGV_CONCAT(
                    adb_args,
                    ARGV(xaprintf("-%c", c),
                         xstrdup(optarg)));
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
            case 'X':
                parse_transport(optarg, &transport, &tcp_addr);
                break;
            case 'Y': {
                const char* sep = strchr(optarg, '=');
                if (sep == NULL)
                    die(EINVAL, "no value for environment variable %s", optarg);
                struct environ_op* eop = xcalloc(sizeof (*eop));
                eop->next = environ_ops;
                eop->name = xstrndup(optarg, sep - optarg);
                eop->value = xstrdup(sep+1);
                environ_ops = eop;
                break;
            }
            case 'K': {
                if (strchr(optarg, '='))
                    die(EINVAL, "invalid environment variable name %s", optarg);
                struct environ_op* eop = xcalloc(sizeof (*eop));
                eop->next = environ_ops;
                eop->name = xstrdup(optarg);
                environ_ops = eop;
                break;
            }
            case 'F': {
                struct environ_op* eop = xcalloc(sizeof (*eop));
                eop->next = environ_ops;
                environ_ops = eop;
                break;
            }
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
                    die(EINVAL, "invalid option -%c", (int) optopt);
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

    // Reverse environ_ops back to argv order.
    environ_ops = reverse_environ_ops(environ_ops);

    // Prepend forwarding so that explicit user environment
    // modifications override.
    forward_envvar(&environ_ops, "LINES");
    forward_envvar(&environ_ops, "COLUMNS");
    forward_envvar(&environ_ops, "TERM");

    if (tty_mode == TTY_AUTO)
        tty_mode = (argc == 0) ? TTY_ENABLE : TTY_DISABLE;

    for (int i = 0; i < 3; ++i)
        if ((tty_mode == TTY_ENABLE && tty_flags[i].tty_p)
            || tty_mode == TTY_SUPER_ENABLE)
        {
            tty_flags[i].want_pty_p = true;
        }

    if (compress)
        for (int i = 0; i < 3; ++i)
            tty_flags[i].compress = true;

    // Here, we want to arrange for SIGWINCH to be delivered only
    // while we're blocked and waiting for IO.  N.B. do _not_ add
    // SIGWINCH to signals_unblock_for_io.  We want to receive this
    // signal only within ppoll.

    block_signal(SIGWINCH);
    signal(SIGWINCH, handle_sigwinch);

    if (transport != transport_shell)
        max_cmdsz = DEFAULT_MAX_CMDSZ_SOCKET;

    size_t command_ringbufsz = max_cmdsz * 4;
    size_t stdio_ringbufsz = max_cmdsz * 2;
    size_t args_to_send = XMAX((size_t) argc + 1, 2);
    struct msg_shex_hello* hello_msg =
        make_hello_msg(max_cmdsz,
                       stdio_ringbufsz,
                       command_ringbufsz,
                       args_to_send,
                       tty_flags);

    if (tty_mode == TTY_SOCKPAIR) {
        hello_msg->stdio_socket_p = 1;
    }

    if (want_ctty)
        hello_msg->ctty_p = 1;

    struct child* child;
    struct child_hello chello;

    reconnect_child:

    if (local_mode) {
        const char* thing_not_supported = NULL;

        if (want_root)
            thing_not_supported = "root update";

        if (transport != transport_shell)
            thing_not_supported = "non-shell transport";

        if (thing_not_supported)
            die(EINVAL,
                "%s not supported in local mode",
                thing_not_supported);

        memset(&chello, 0, sizeof (chello));
        child = start_stub_local();
    } else {
        child = start_stub_adb(force_send_stub, adb_args, &chello);
    }

    struct childcom tc_buf = {
        .to_child = child->fd[0],
        .from_child = child->fd[1],
        .writer = write_all_adb_encoded,
    };

    struct childcom* tc = &tc_buf;

    // On Lollipop (API level >= 21), SELinux is strict and will not
    // let us inherit a working socket file descriptor across a
    // cross-domain exec.  In that environment, we need to exec first
    // and _then_ rebind.  We prefer to rebind and then exec in other
    // environments so that we can use the socket transport for users
    // that don't have network access.

    dbg("remote API level is %u", chello.api_level);

    if (chello.api_level < 21) {
        if (transport == transport_unix)
            tc = reconnect_over_unix_socket(tc, adb_args);
        else if (transport == transport_tcp)
            tc = reconnect_over_tcp_socket(tc, child, tcp_addr);
    }

    if (chello.api_level >= 21) {
        // See the comments in re_exec_as_root over in cmd_stub.c for
        // the reason we need this hack.  On API level 21 and above,
        // we use a shell thunk unconditionally, but a few downlevel
        // devices also need it, so handle this rare case by catching
        // errors arising from this condition and trying again below.
        shell_thunk = true;
    }

    if (want_root && chello.uid != 0)
        command_re_exec_as_root(tc);

    if (want_user) {
        if (command_re_exec_as_user(tc, want_user, shell_thunk) ==
            RE_EXEC_STUB_NEEDED)
        {
            shell_thunk = true;
            child_kill(child, SIGTERM);
            child_wait(child);
            goto reconnect_child;
        }
    }

    if (chello.api_level >= 21) {
        if (transport == transport_unix)
            tc = reconnect_over_unix_socket(tc, adb_args);
        else if (transport == transport_tcp)
            tc = reconnect_over_tcp_socket(tc, child, tcp_addr);
    }

    tc_sendmsg(tc, &hello_msg->msg);

    if (child_chdir)
        send_chdir(tc, child_chdir);

    send_environ_ops(tc, environ_ops);
    send_cmdline(tc, argc, argv, exename);

    struct fb_adb_shex shex;
    memset(&shex, 0, sizeof (shex));
    struct fb_adb_sh* sh = &shex.sh;

    // Make sure that within ppoll, we atomically unblock SIGWINCH so
    // that ppoll fails with EINTR and we don't lose any signals.
    // N.B. changes to signals_unblock_for_io after this point will
    // not be reflected in poll_sigmask, so don't change
    // signals_unblock_for_io.

    sigset_t poll_sigmask;
    VERIFY(sigprocmask(SIG_BLOCK, NULL, &poll_sigmask) == 0);
    sigdelset(&poll_sigmask, SIGWINCH);
    for (int i = 1; i < NSIG; ++i)
        if (sigismember(&signals_unblock_for_io, i)) {
            sigdelset(&poll_sigmask, i);
        }
    sh->poll_sigmask = &poll_sigmask;

    sh->max_outgoing_msg = max_cmdsz;
    sh->process_msg = shex_process_msg;
    sh->nrch = 5;
    struct channel** ch = xalloc(sh->nrch * sizeof (*ch));

    ch[FROM_PEER] = channel_new(tc->from_child,
                                command_ringbufsz,
                                CHANNEL_FROM_FD);
    ch[FROM_PEER]->window = UINT32_MAX;

    ch[TO_PEER] = channel_new(tc->to_child,
                              command_ringbufsz,
                              CHANNEL_TO_FD);
    ch[TO_PEER]->adb_encoding_hack =
        (tc->writer == write_all_adb_encoded);

    // Here, we turn off the optimization that lets us writev(2)
    // directly to TO_PEER when TO_PEER's ring buffer is empty.
    // In principle, by disabling this optimization, we can coalesce
    // outbound IOs into bigger chunks, since we combine lots of them
    // into the outbound ring buffer before trying to empty that ring
    // buffer into the socket buffer.
    //
    // IO timing is fraught, so let's just do this for now.
    //

    ch[TO_PEER]->always_buffer = true;

    ch[CHILD_STDIN] = channel_new(fdh_dup(0),
                                  stdio_ringbufsz,
                                  CHANNEL_FROM_FD);
    ch[CHILD_STDIN]->track_window = true;
    ch[CHILD_STDIN]->compress = compress;

    ch[CHILD_STDOUT] = channel_new(fdh_dup(1),
                                   stdio_ringbufsz,
                                   CHANNEL_TO_FD);
    ch[CHILD_STDOUT]->track_bytes_written = true;
    ch[CHILD_STDOUT]->compress = compress;
    ch[CHILD_STDOUT]->bytes_written =
        ringbuf_room(ch[CHILD_STDOUT]->rb);

    ch[CHILD_STDERR] = channel_new(fdh_dup(2),
                                   stdio_ringbufsz,
                                   CHANNEL_TO_FD);
    ch[CHILD_STDERR]->track_bytes_written = true;
    ch[CHILD_STDERR]->compress = compress;
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
    dbgch("upon closing", ch, sh->nrch);

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

// These options are ones that we pass to rcmd instead of invoked
// scripts.  The short forms also need to be on
// shex_wrapper_common_ops.

static const struct option shex_wrapper_common_longops[] = {
    { "root", no_argument, NULL, 'r' },
    { "user", required_argument, NULL, 'u' },
    { 0 }
};

static const char shex_wrapper_common_opts[] = "des:p:H:P:ru:";

int
shex_wrapper(const char* wrapped_cmd,
             const char* opts,
             const struct option* longopts,
             const char* usage,
             const char** argv)
{
    const char* const* rcmd_args = empty_argv;
    const char* const* remote_args = empty_argv;
    const char* arg;
    bool posix_correct = false;
    char c;

    if (opts != NULL) {
        while (strchr("+:", opts[0])) {
            if (opts[0] == '+')
                posix_correct = true;
            ++opts;
        }

#ifndef NDEBUG
        for (const char* p = opts; *p; ++p) {
            if (*p != ':' && strchr(shex_wrapper_common_opts, *p)) {
                assert(!"conflicting options in shex_wrapper!");
            }
        }
#endif
    }

#define ADDARG(_dest, _arg)                             \
    (*(_dest) = ARGV_CONCAT(*(_dest), ARGV((_arg))))

    ADDARG(&rcmd_args, *argv++);

    // Split the argument list into arguments for rcmd and arguments
    // for the remote command.

    while ((arg = *argv++)) {
        if ((posix_correct && arg[0] != '-') ||
            (arg[0] == '-' && arg[1] == '-' && arg[2] == '\0'))
        {
            remote_args = ARGV_CONCAT(remote_args, argv - 1);
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

            bool rcmd = true;
            const struct option* longopt =
                find_option_by_name(shex_wrapper_common_longops,
                                    longname);

            if (longopt == NULL && longopts) {
                longopt = find_option_by_name(longopts, longname);
                rcmd = false;
            }

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

            ADDARG((rcmd ? &rcmd_args : &remote_args),
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

            if ((ap = strchr(shex_wrapper_common_opts, c)))
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
        "fb-adb",
        wrapped_cmd,
        NULL
    };

    const char** nargv =
        ARGV_CONCAT(rcmd_args, invoke_self_args, remote_args);

    return shex_main_common(SHEX_MODE_RCMD,
                            argv_count(nargv),
                            nargv);

#undef ADDARG
}
