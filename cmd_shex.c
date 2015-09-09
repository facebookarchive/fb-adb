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
#include "autocmd.h"
#include "strutil.h"
#include "net.h"
#include "xmkraw.h"
#include "fs.h"
#include "elfid.h"

#define ARG_DEFAULT_SH ((const char*)MSG_CMDLINE_DEFAULT_SH)
#define ARG_DEFAULT_SH_LOGIN ((const char*)MSG_CMDLINE_DEFAULT_SH_LOGIN)
#define ARG_EXEC_FILE ((const char*)MSG_CMDLINE_EXEC_FILE)

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

struct child_hello {
    char ver[FB_ADB_FINGERPRINT_LENGTH+1];
    unsigned abi_mask;
    unsigned uid;
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
           &chello->ver[0],
           &chello->abi_mask,
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
    xflush(tmpfile);

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
    if (remote_debug) {
        if (remote_debug[0] != '>')
            die(EINVAL, "remote debugging must dump to file: "
                "otherwise, debug output will interfere with "
                "fb-adb protocol.");
        cmd = xaprintf("FB_ADB_DEBUG='%s' exec %s stub",
                       remote_debug,
                       adb_name);
    }
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

    if (parse_child_hello(resp, chello) &&
        !strcmp(chello->ver, build_fingerprint))
    {
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
start_stub_adb(const char* const* adb_args,
               struct child_hello* chello)
{
    const struct child_start_info csi = {
        .flags = CHILD_INHERIT_STDERR,
        .exename = "adb",
        .argv = ARGV_CONCAT(ARGV("adb"), adb_args, ARGV("shell")),
    };

    struct child* child = NULL;
    char* err = NULL;
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
    unsigned our_very_own_open_file_description : 1;
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
send_cmdline_argument(const struct childcom* tc, const void* val)
{
    struct msg m;
    size_t valsz;
    size_t totalsz;
    uint16_t type;

    if (val == ARG_DEFAULT_SH) {
        val = NULL;
        valsz = 0;
        type = MSG_CMDLINE_DEFAULT_SH;
    } else if (val == ARG_DEFAULT_SH_LOGIN) {
        val = NULL;
        valsz = 0;
        type = MSG_CMDLINE_DEFAULT_SH_LOGIN;
    } else if (val == ARG_EXEC_FILE) {
        val = NULL;
        valsz = 0;
        type = MSG_CMDLINE_EXEC_FILE;
    } else {
        valsz = strlen((const char*)val);
        type = MSG_CMDLINE_ARGUMENT;
    }

    if (SATADD(&totalsz, sizeof (m), valsz) || totalsz > UINT32_MAX)
        die(EINVAL, "command line argument too long");

    if (totalsz <= MSG_MAX_SIZE) {
        m.type = type;
        m.size = totalsz;
        tc_write(tc, &m, sizeof (m));
        tc_write(tc, val, valsz);
    } else {
        assert(type == MSG_CMDLINE_ARGUMENT);
        struct msg_cmdline_argument_jumbo mj;
        memset(&mj, 0, sizeof (mj));
        mj.msg.type = MSG_CMDLINE_ARGUMENT_JUMBO;
        mj.msg.size = sizeof (mj);
        mj.actual_size = valsz;
        tc_write(tc, &mj, sizeof (mj));
        tc_write(tc, val, valsz);
    }
}

static void
lim_format_shell_command_line(const char* command,
                              const char *const* argv,
                              size_t *pos,
                              char *buf,
                              size_t bufsz)
{
    if (command != NULL) {
        /* Special case: don't quote the first argument. */
        lim_strcat(command, pos, buf, bufsz);
    }

    while (*argv != NULL) {
        lim_outc(' ', pos, buf, bufsz);
        lim_shellquote(*argv++, pos, buf, bufsz);
    }
}

static void
send_cmdline(const struct childcom* tc,
             const char* exename,
             const char* command,
             const char* const* argv)
{
    send_cmdline_argument(tc, exename ?: command);
    send_cmdline_argument(tc, command);
    while (*argv)
        send_cmdline_argument(tc, *argv++);
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

        die_rethrow(&ei);
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
                 system_tempdir(),
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

static void
try_hack_reopen_tty_1 (void* data)
{
    hack_reopen_tty((int)(intptr_t)data);
}

static bool
try_hack_reopen_tty (int fd)
{
    struct errinfo* eip = NULL;
#ifndef NDEBUG
    struct errinfo ei = {
        .want_msg = true,
    };

    eip = &ei;
#endif

    bool success = !catch_error(try_hack_reopen_tty_1,
                                (void*) (intptr_t) fd,
                                eip);

#ifndef NDEBUG
    if (!success)
        dbg("hack_reopen_tty failed: %d: %s", ei.err, ei.msg);
#endif

    return success;
}

struct reset_termios_context {
    struct channel** ch; // Starting with CHILD_STDIN
    struct sigtstp_cookie* sigtstp_registration;
    unsigned nrch;
    struct termios* scratch;
    bool saved_old_sigmask;
    sigset_t old_sigmask;
};

static void
reset_termios_on_sigtstp(enum sigtstp_mode mode, void* data)
{
    struct reset_termios_context* rtc = data;
    unsigned nrch = rtc->nrch;
    struct channel** ch = rtc->ch;

    if (mode == SIGTSTP_BEFORE_SUSPEND) {
        dbg("[jc] SIGTSTP_BEFORE_SUSPEND");
        for (unsigned i = 0; i < nrch; ++i) {
            struct channel* c = ch[i];
            if (c->saved_term_state != NULL && c->fdh != NULL)
                ttysave_before_suspend(c->saved_term_state, c->fdh->fd);
        }
    } else if (mode == SIGTSTP_AFTER_RESUME) {
        dbg("[jc] SIGTSTP_AFTER_RESUME");
        for (unsigned i = 0; i < nrch; ++i) {
            struct channel* c = ch[i];
            if (c->saved_term_state != NULL && c->fdh != NULL)
                ttysave_after_resume(c->saved_term_state, c->fdh->fd);
        }
    } else if (mode == SIGTSTP_AFTER_UNEXPECTED_SIGCONT) {
        dbg("[jc] unexpected SIGCONT");
        for (unsigned i = 0; i < nrch; ++i) {
            struct channel* c = ch[i];
            if (c->saved_term_state != NULL && c->fdh != NULL)
                ttysave_after_sigcont(c->saved_term_state, c->fdh->fd);
        }
    }
}

static void
cleanup_reset_termios(void* data)
{
    struct reset_termios_context* rtc = data;

    unsigned nrch = rtc->nrch;
    struct channel** ch = rtc->ch;

    for (unsigned i = 0; i < nrch; ++i) {
        struct channel* c = ch[i];
        if (c->saved_term_state != NULL && c->fdh != NULL) {
            unsigned ttysave_flags = (c->dir == CHANNEL_TO_FD)
                ? RAW_OUTPUT
                : RAW_INPUT;
            ttysave_restore(c->saved_term_state,
                            c->fdh->fd,
                            ttysave_flags);
            c->saved_term_state = NULL;
        }
    }

    if (rtc->sigtstp_registration)
        sigtstp_unregister(rtc->sigtstp_registration);
}

static void
setup_reset_termios(
    struct reset_termios_context* rtc,
    struct tty_flags* tty_flags,
    struct channel** ch,
    unsigned nrch)
{
    SCOPED_RESLIST(rl);

    struct cleanup* cl_reset_termios = NULL;

    for (unsigned i = 0; i < nrch; ++i)
        if (tty_flags[i].tty_p && tty_flags[i].want_pty_p) {
            cl_reset_termios = cleanup_allocate();
            break;
        }

    if (cl_reset_termios == NULL) {
        dbg("doing nothing special for job control: no TTYs");
        return;
    }

    memset(rtc, 0, sizeof (*rtc));
    rtc->ch = ch;
    rtc->nrch = nrch;
    cleanup_commit(cl_reset_termios, cleanup_reset_termios, rtc);

    rtc->sigtstp_registration = sigtstp_register(
        reset_termios_on_sigtstp, rtc);

    for (unsigned i = 0; i < nrch; ++i)
        if (tty_flags[i].tty_p && tty_flags[i].want_pty_p) {
            struct channel* c = ch[i];
            assert(c->saved_term_state == NULL);
            unsigned ttysave_flags = (c->dir == CHANNEL_TO_FD)
                ? RAW_OUTPUT
                : RAW_INPUT;
            c->saved_term_state = ttysave_make_raw(
                c->fdh->fd, ttysave_flags);
        }

    dbg("successfully set up TTYs");
    reslist_xfer(rl->parent, rl);
}

struct shex_common_info {
    struct adb_opts adb;
    struct user_opts user;
    struct cwd_opts cwd;
    struct shex_opts shex;
    struct transport_opts transport;
    const char* command;
    const char** args;
    struct strlist* xcmd_candidates;
};

static struct environ_op*
parse_uenvops(const struct strlist* uenvops)
{
    struct environ_op* environ_ops = NULL;
    for (const char* uenvop = strlist_rewind(uenvops);
         uenvop != NULL;
         uenvop = strlist_next(uenvops))
    {
        if (string_starts_with_p(uenvop, "setenv=")) {
            const char* varname = uenvop + strlen("setenv=");
            const char* sep = strchr(varname, '=');
            if (sep == NULL)
                usage_error(
                    "no value for environment variable %s",
                    varname);
            struct environ_op* eop = xcalloc(sizeof (*eop));
            eop->next = environ_ops;
            eop->name = xstrndup(varname, sep - varname);
            eop->value = sep+1;
            environ_ops = eop;
        } else if (string_starts_with_p(uenvop, "unsetenv=")) {
            const char* varname = uenvop + strlen("unsetenv=");
            if (strchr(varname, '='))
                usage_error(
                    "invalid environment variable name %s",
                    varname);
            struct environ_op* eop = xcalloc(sizeof (*eop));
            eop->next = environ_ops;
            eop->name = varname;
            environ_ops = eop;
        } else if (!strcmp(uenvop, "clearenv")) {
            struct environ_op* eop = xcalloc(sizeof (*eop));
            eop->next = environ_ops;
            environ_ops = eop;
        } else {
            abort();
        }
    }

    return environ_ops; // Reversed at this point
}

__attribute__((unused))
static const char*
describe_abi_mask(unsigned abi_mask)
{
    const char* description = "";
    static const struct {
        const char* name;
        unsigned bit;
    } abi_names[] = {
        {"FB_ADB_ARCH_X86",      FB_ADB_ARCH_X86 },
        {"FB_ADB_ARCH_ADM64",    FB_ADB_ARCH_AMD64 },
        {"FB_ADB_ARCH_ARM",      FB_ADB_ARCH_ARM },
        {"FB_ADB_ARCH_AARCH64",  FB_ADB_ARCH_AARCH64 },
    };

    while (abi_mask != 0) {
        const char* abi_name = NULL;
        for (size_t i = 0; abi_name == NULL
                 && i < ARRAYSIZE(abi_names); ++i)
        {
            if (abi_mask && abi_names[i].bit) {
                abi_name = abi_names[i].name;
                abi_mask &= ~abi_names[i].bit;
                break;
            }
        }

        if (abi_name == NULL) {
            abi_name = xaprintf("[unknown: 0x%08x]", abi_mask);
            abi_mask = 0;
        }

        if (description[0] == '\0') {
            description = abi_name;
        } else {
            description = xaprintf("%s,%s", description, abi_name);
        }
    }

    if (description[0] == '\0')
        description = "[none]";

    return description;
}

static void
send_open_exec_file(const struct childcom* tc,
                    const struct sha256_hash* hash,
                    int candidate_fd,
                    const char* exe_basename)
{
    size_t exe_basename_length = strlen(exe_basename);
    size_t msglen = sizeof (struct msg_open_exec_file);
    if (SATADD(&msglen, msglen, exe_basename_length) ||
        msglen > MSG_MAX_SIZE)
        die(EINVAL, "xcmd proram name too long");
    struct msg_open_exec_file oef = {
        .msg.size = msglen,
        .msg.type = MSG_OPEN_EXEC_FILE,
    };

    _Static_assert(
        sizeof (oef.expected_sha256_hash) <= sizeof (hash->digest),
        "hash size mismatch");

    memcpy(&oef.expected_sha256_hash[0],
           hash->digest,
           sizeof (oef.expected_sha256_hash));

    tc_write(tc, &oef, sizeof (oef));
    tc_write(tc, exe_basename, exe_basename_length);
}

static void
send_file_to_device_pre_exec(void* data)
{
    int fd = (intptr_t) data;
    if (dup2(fd, STDIN_FILENO) == -1)
        die_errno("dup2");
}

static void
send_file_to_device(
    const struct adb_opts* adb,
    const struct transport_opts* transport,
    const struct user_opts* user,
    int fd,
    const char* device_file_name,
    mode_t mode)
{
    SCOPED_RESLIST(rl);

    dbg("sending file to device: remote name [%s]",
        device_file_name);

    struct strlist* args = strlist_new();
    strlist_append(args, orig_argv0);
    strlist_append(args, "fput");

    struct cmd_fput_info fpi = {
        .adb = *adb,
        .transport = *transport,
        .user = *user,
        .xfer.write_mode = "atomic",
        .xfer.mode = xaprintf("%o", mode),
        .local = "-",
        .remote = device_file_name,
    };

    strlist_xfer(args, make_args_cmd_fput(CMD_ARG_ALL, &fpi));

    struct child_start_info csi = {
        .flags = (CHILD_NULL_STDIN |
                  CHILD_NULL_STDOUT |
                  CHILD_INHERIT_STDERR),
        .pre_exec = send_file_to_device_pre_exec,
        .pre_exec_data = (void*) (intptr_t) fd,
        .exename = my_exe(),
        .argv = strlist_to_argv(args),
    };

    int exit_code = child_status_to_exit_code(
        child_wait(child_start(&csi)));

    if (exit_code != 0)
        die(EIO, "failed sending file to device");
}

static int
find_xcmd_candidate(
    const char* program,
    const struct strlist* candidates,
    unsigned api_level,
    unsigned abi_mask)
{
    for (const char* candidate = strlist_rewind(candidates);
         candidate != NULL;
         candidate = strlist_next(candidates))
    {
        SCOPED_RESLIST(rl);
        int candidate_fd = try_xopen(candidate, O_RDONLY, 0);
        if (candidate_fd == -1) {
            dbg("could not open candidate %s: %s",
                candidate, strerror(errno));
            continue;
        }

        dbg("testing candidate %s for compatibility", candidate);
        if (elf_compatible_p(candidate_fd, api_level, abi_mask)) {
            dbg("candidate is compatible");
            reslist_xfer(rl->parent, rl);
            return candidate_fd;
        }
    }

    die(ENOENT, "no suitable candidate found for xcmd %s", program);
}

static bool
handle_open_exec_response(const struct shex_common_info* info,
                          const struct childcom* tc,
                          int candidate_fd)
{
    SCOPED_RESLIST(rl);

    struct msg* msg = tc_recvmsg(tc);
    if (msg->type == MSG_EXEC_FILE_OK)
        return true;

    if (msg->type != MSG_EXEC_FILE_MISMATCH)
        die(ECOMM, "unexpected message type");

    struct msg_exec_file_mismatch* efm =
        CHECK_MSG_CAST(
            msg,
            struct msg_exec_file_mismatch);

    char* filename_to_update = xstrndup(
        efm->filename_to_update,
        efm->msg.size - offsetof(struct msg_exec_file_mismatch,
                                 filename_to_update));


    xrewindfd(candidate_fd);
    send_file_to_device(&info->adb,
                        &info->transport,
                        &info->user,
                        candidate_fd,
                        filename_to_update,
                        0500 /* -r-x------ */);
    return false;
}

static int
shex_main_common(const struct shex_common_info* info)
{
    size_t max_cmdsz = DEFAULT_MAX_CMDSZ;
    bool local_mode = false;
    enum { TTY_AUTO,
           TTY_SOCKPAIR,
           TTY_DISABLE,
           TTY_ENABLE,
           TTY_SUPER_ENABLE } tty_mode = TTY_AUTO;

    struct tty_flags tty_flags[3];
    struct strlist* adb_args_list = strlist_new();
    emit_args_adb_opts(adb_args_list, &info->adb);
    const char* const* adb_args = strlist_to_argv(adb_args_list);
    bool want_root = false;
    const char* want_user = NULL;
    enum transport transport = transport_shell;
    const char* tcp_addr = NULL;
    bool compress = !getenv("FB_ADB_NO_COMPRESSION");
    bool shell_thunk = false;

    const char* transport_env = getenv("FB_ADB_TRANSPORT");
    if (transport_env)
        parse_transport(transport_env, &transport, &tcp_addr);

    struct environ_op* environ_ops = NULL;

#ifndef NDEBUG
    local_mode = !!getenv("FB_ADB_LOCAL_MODE");
#endif

    memset(&tty_flags, 0, sizeof (tty_flags));
    for (int i = 0; i < 3; ++i)
        if (isatty(i)) {
            tty_flags[i].tty_p = true;
            if (try_hack_reopen_tty(i)) {
                tty_flags[i].our_very_own_open_file_description = true;
                dbg("got new file description for fd %d", i);
            }
        }

    if (info->user.root) {
        if (info->user.user)
            usage_error("cannot both run-as user and su to root");
        want_root = true;
    }

    if (info->user.user) {
        if (info->user.root)
            usage_error("cannot both run-as user and su to root");
        want_user = info->user.user;
    }

    const struct strlist* termops = info->shex.termops;
    if (termops) {
        for (const char* termop = strlist_rewind(termops);
             termop != NULL;
             termop = strlist_next(termops))
        {
            if (!strcmp(termop, "force-tty")) {
                if (tty_mode == TTY_ENABLE)
                    tty_mode = TTY_SUPER_ENABLE;
                else
                    tty_mode = TTY_ENABLE;
            } else if (!strcmp(termop, "disable-tty")) {
                tty_mode = TTY_DISABLE;
            } else {
                abort();
            }
        }
    }

    if (info->shex.uenvops)
        environ_ops = parse_uenvops(info->shex.uenvops);

    const char* utransport = info->transport.transport;

    if (utransport)
        parse_transport(utransport, &transport, &tcp_addr);

    // Prepend forwarding so that explicit user environment
    // modifications override.
    forward_envvar(&environ_ops, "LINES");
    forward_envvar(&environ_ops, "COLUMNS");
    forward_envvar(&environ_ops, "TERM");

    // Reverse environment operations back to specification order.
    environ_ops = reverse_environ_ops(environ_ops);

    const char* command = info->command;
    const char* const* argv = info->args;

    if (tty_mode == TTY_AUTO)
        tty_mode = ( command == ARG_DEFAULT_SH_LOGIN
                     ? TTY_ENABLE
                     : TTY_DISABLE );

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
    struct msg_shex_hello* hello_msg =
        make_hello_msg(max_cmdsz,
                       stdio_ringbufsz,
                       command_ringbufsz,
                       2 + argv_count(argv),
                       tty_flags);

    if (tty_mode == TTY_SOCKPAIR) {
        hello_msg->stdio_socket_p = 1;
    }

    if (info->shex.no_ctty == 0)
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
        child = start_stub_adb(adb_args, &chello);
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
    dbg("remote ABI support: %s", describe_abi_mask(chello.abi_mask));

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

    if (info->cwd.chdir)
        send_chdir(tc, info->cwd.chdir);

    if (info->xcmd_candidates != NULL) {
        SCOPED_RESLIST(rl_xcmd);
        int candidate_fd = find_xcmd_candidate(
            info->command,
            info->xcmd_candidates,
            chello.api_level,
            chello.abi_mask);
        xrewindfd(candidate_fd);
        struct sha256_hash hash = sha256_fd(candidate_fd);
        do {
            send_open_exec_file(tc, &hash, candidate_fd, info->command);
        } while (!handle_open_exec_response(info, tc, candidate_fd));
    }

    send_environ_ops(tc, environ_ops);
    send_cmdline(tc, info->shex.exename, command, argv);

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

    struct reset_termios_context rtc;
    setup_reset_termios(&rtc, &tty_flags[0], &ch[CHILD_STDIN], 3);

#ifdef FBADB_CHANNEL_NONBLOCK_HACK
    for (int fd = 0; fd < 3; ++fd) {
        int chno = CHILD_STDIN + fd;
        if (tty_flags[fd].tty_p &&
            !tty_flags[fd].our_very_own_open_file_description)
        {
            // We're not able to create our own open file description
            // for this tty, so instead use SIGALRM-based poor man's
            // "non-blocking" reads that time out as soon as the
            // system's clock ticks over.
            dbg("enabling non-blocking emulation hack for "
                "channel %d (real fd %d)",
                chno, ch[chno]->fdh->fd);
            ch[chno]->nonblock_hack = true;
        }
    }
#endif

    sh->ch = ch;

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
shell_main(const struct cmd_shell_info* info)
{
    struct shex_common_info cinfo = {
        .adb = info->adb,
        .user = info->user,
        .cwd = info->cwd,
        .shex = info->shex,
        .transport = info->transport,
    };

    const char* command = info->command;
    if (command == NULL) {
        cinfo.shex.exename = ARG_DEFAULT_SH;
        cinfo.command = ARG_DEFAULT_SH_LOGIN;
        cinfo.args = (const char**) empty_argv;
    } else {
        const char* const* argv = info->args;
        size_t sz = 0;
        lim_format_shell_command_line(command, argv, &sz, NULL, 0);
        char* script = xalloc(sz + 1);
        size_t pos = 0;
        lim_format_shell_command_line(command, argv, &pos, script, sz);
        script[pos] = '\0';
        cinfo.command = ARG_DEFAULT_SH;
        cinfo.args = ARGV("-c", script);
    }

    return shex_main_common(&cinfo);
}

int
rcmd_main(const struct cmd_rcmd_info* info)
{
    struct shex_common_info cinfo = {
        .adb = info->adb,
        .user = info->user,
        .cwd = info->cwd,
        .shex = info->shex,
        .transport = info->transport,
        .command = info->command,
        .args = info->args,
    };
    return shex_main_common(&cinfo);
}

int
xcmd_main(const struct cmd_xcmd_info* info)
{
    struct strlist* candidates = strlist_new();
    const char* program = info->program;

    if (strchr(program, '/'))
        usage_error("PROGRAM option to xcmd cannot contain slashes");

    if (program[0] == '\0')
        usage_error("PROGRAM option to xcmd cannot be empty");

    if (info->shex.exename)
        usage_error("--exename makes no sense with xcmd");

    if (info->xcmd.candidates != NULL) {
        const struct strlist* explicit_candidates = info->xcmd.candidates;
        for (const char* carg = strlist_rewind(explicit_candidates);
             carg != NULL;
             carg = strlist_next(explicit_candidates))
        {
            const char* prefix = "candidate=";
            if (!string_starts_with_p(carg, prefix))
                die(EINVAL, "invalid candidate option");
            strlist_append(candidates, carg + strlen(prefix));
        }
    }

    const char* candidate_path = info->xcmd.candidate_path;
    if (candidate_path == NULL)
        candidate_path = getenv("FB_ADB_XCMD_PATH");

    if (candidate_path != NULL) {
        char* saveptr = NULL;
        char* s = xstrdup(candidate_path);
        for (const char* c = strtok_r(s, ":", &saveptr);
             c != NULL;
             c = strtok_r(NULL, ":", &saveptr))
        {
            strlist_append(candidates, xaprintf("%s/%s", c, program));
        }
    }

    if (strlist_empty_p(candidates))
        usage_error("no candidates given for xcmd and "
                    "candidate path empty");

    struct shex_common_info cinfo = {
        .adb = info->adb,
        .user = info->user,
        .cwd = info->cwd,
        .shex = info->shex,
        .shex.exename = ARG_EXEC_FILE,
        .transport = info->transport,
        .command = info->program,
        .args = info->args,
        .xcmd_candidates = candidates,
    };
    return shex_main_common(&cinfo);
}
