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
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include "stubdaemon.h"
#include "util.h"
#include "fs.h"
#include "net.h"
#include "constants.h"
#include "child.h"
#include "argv.h"
#include "strutil.h"
#include "core.h"
#include "androidmsg.h"
#include "timestamp.h"

#define DAEMON_REPLY_OKAY 'o'
#define DAEMON_COMMAND_KILL_SELF 'k'
#define DAEMON_COMMAND_PING 'p'

static int
fb_adb_service_connect(const char* package, int timeout_ms)
{
    SCOPED_RESLIST(rl);

#ifdef SO_PEERCRED
    uid_t expected_uid = xstat(xaprintf("/data/data/%s", package)).st_uid;
#endif

    const char* service_sockname =
        xaprintf("fb-adb-service-%s",
                 gen_hex_random(ENOUGH_ENTROPY));
    int service_listen_fd = xsocket(AF_UNIX, SOCK_STREAM, 0);
    xbind(service_listen_fd,
          make_addr_unix_abstract(service_sockname,
                                  strlen(service_sockname)));
    xlisten(service_listen_fd, 1);

    struct child_start_info csi = {
        .io[STDIN_FILENO] = CHILD_IO_DEV_NULL,
        .io[STDOUT_FILENO] = CHILD_IO_PIPE,
        .io[STDERR_FILENO] = CHILD_IO_DUP_TO_STDOUT,
        .exename = "am",
        .argv = ARGV(
            "am",
            "startservice",
            "-n",
            xaprintf("%s/%s",
                     package,
                     "com.facebook.fbadb.FbAdbService"),
            "-a", "callMeCallMeAnyTime",
            "-e", "com.facebook.fbadb.SOCKET_NAME", service_sockname),
    };

    struct child* am = child_start(&csi);
    // am doesn't use exit status to indicate that it worked, so look
    // for the success string in its output.  (But if we _do_ see a
    // non-zero exit status, we know it definitely failed.)

    FILE* am_out = xfdopen(am->fd[1]->fd, "r");
    for (;;) {
        SCOPED_RESLIST(rl_line);
        size_t linesz;
        char* line = slurp_line(am_out, &linesz);
        if (line == NULL)
            break;
        if (string_starts_with_p(line, "Error: ")) {
            rtrim(line, &linesz, "\r\n");
            die(ECOMM,
                "starting fb-adb service for package %s failed: %s",
                package,
                line + strlen("Error: "));
        }
    }

    if (!child_status_success_p(child_wait(am)))
        die(ECOMM, "unclear error running am");

    set_timeout_ms(timeout_ms,
                   ETIMEDOUT,
                   "timeout waiting for service callback");
    WITH_CURRENT_RESLIST(rl->parent);
    int connection = xaccept(service_listen_fd);
#ifdef SO_PEERCRED
    uid_t connection_uid = get_peer_credentials(connection).uid;
    if (connection_uid != expected_uid)
        die(ECOMM, "expected uid %d for package [%s] "
            "but peer has uid %d",
            (int) expected_uid,
            package,
            (int) connection_uid);
#endif
    return connection;
}

void
start_daemon_via_service_hack(const char* package_name)
{
    SCOPED_RESLIST(rl);

    int peer_fd = fb_adb_service_connect(
        package_name,
        SERVICE_HACK_CALLBACK_TIMEOUT_MS);

#define SCRIPT_TEMPLATE                                                 \
    "set -e -- %s \".fb-adb.tmp.$$\"; "                                 \
        "if ! /system/bin/cmp .fb-adb \"$1\" >/dev/null 2>&1; then "    \
        "  /system/bin/cat \"$1\" > \"$2\"; "                           \
        "  if ! /system/bin/chmod 555 \"$2\" || "                       \
        "     ! " MV_F " \"$2\" .fb-adb; then "                         \
        "    " RM_F " \"$2\" || true; "                                 \
        "    exit 1;"                                                   \
        "  fi; "                                                        \
        "fi; "                                                          \
        "exec ./.fb-adb stub -ld"

    // Android 4.0 lacks support for the -f option, but redirecting
    // stdin from /dev/null suppresses any interactive prompts;
    // Android 6.0 broke this /dev/null trick, but does support the -f
    // option.
    // See
    // https://code.google.com/p/android-developer-preview/issues/detail?id=3096.

    static const char script_template_lollipop[] =
#define MV_F "/system/bin/mv -f"
#define RM_F "/system/bin/rm -f"
        SCRIPT_TEMPLATE;
#undef MV_F
#undef RM_F

    static const char script_template_downlevel[] =
#define MV_F "</dev/null /system/bin/mv"
#define RM_F "</dev/null /system/bin/rm"
        SCRIPT_TEMPLATE;
#undef MV_F
#undef RM_F

    // Put the whole script inside an eval so that we're guaranteed to
    // read the whole input before trying to run any of it.
    char* script = xaprintf("eval %s\n",
                            xshellquote(
                                xaprintf(
                                    ( api_level() > 19
                                      ? script_template_lollipop
                                      : script_template_downlevel ),
                                    xshellquote(xrealpath(orig_argv0)))));
    size_t script_length = strlen(script);
    if (script_length > INT32_MAX)
        die(ECOMM, "start-service script too large");
    int32_t script_length_be = htonl(script_length);
    write_all(peer_fd, &script_length_be, sizeof (script_length_be));
    write_all(peer_fd, script, script_length);

    char* output = slurp_fd(peer_fd, NULL);
    char* endptr = NULL;
    char* error = NULL;
    bool found_daemon_hello = false;

    for (char* line = strtok_r((output), "\n", &endptr);
         line != NULL;
         line = strtok_r(NULL, "\n", &endptr))
    {
        struct daemon_hello dhello;
        if (!found_daemon_hello &&
            parse_daemon_hello(line, &dhello))
        {
            xprintf(xstdout, "%s\n", line);
            xflush(xstdout);
            found_daemon_hello = true;
        } else if (error == NULL) {
            rtrim(line, NULL, "\r\n");
            error = line;
        }
    }

    if (!found_daemon_hello)
        die(ECOMM, "error starting service: %s", error ?: "[unknown]");
}

static char*
make_daemon_socket_name_file_name(void)
{
    return xaprintf("%s/daemon-socket-name", my_fb_adb_directory());
}

static char*
read_daemon_socket_name(void)
{
    SCOPED_RESLIST(rl);
    int socket_name_file =
        xopen(make_daemon_socket_name_file_name(), O_RDONLY, 0);
    xflock(socket_name_file, LOCK_SH);
    WITH_CURRENT_RESLIST(rl->parent);
    return slurp_fd(socket_name_file, NULL);
}

static int
connect_to_daemon_control(void)
{
    SCOPED_RESLIST(rl);
    char* control_socket_name =
        xaprintf("%s%s",
                 read_daemon_socket_name(),
                 DAEMON_CONTROL_SUFFIX);
    struct addr* control_addr =
        make_addr_unix_abstract(
            control_socket_name,
            strlen(control_socket_name));
    WITH_CURRENT_RESLIST(rl->parent);
    int control_connection = xsocket(AF_UNIX, SOCK_STREAM, 0);
    xconnect(control_connection, control_addr);
    return control_connection;
}

static char
send_control_command(char command)
{
    SCOPED_RESLIST(rl);
    int control_connection = connect_to_daemon_control();
    write_all(control_connection, &command, sizeof (command));
    char reply = 0;
    (void) read_all(control_connection, &reply, sizeof (reply));
    return reply;
}

void
stop_daemon(void)
{
    char reply = send_control_command(DAEMON_COMMAND_KILL_SELF);
    if (reply != DAEMON_REPLY_OKAY)
        die(EINVAL, "unexpected reply from server control: %hhd", reply);
}

static void
try_stop_daemon_1(void* data)
{
    stop_daemon();
}

static void
try_stop_daemon(void)
{
    struct errinfo ei = ERRINFO_WANT_MSG_IF_DEBUG;
    if (catch_error(try_stop_daemon_1, NULL, &ei))
        dbg("failed to stop daemon: %s", ei.msg);
    else
        dbg("stopped running daemon");
}

static void
write_daemon_hello(int fd, const char* socket_name, unsigned pid)
{
    SCOPED_RESLIST(rl);
    char* hello = xaprintf(FB_ADB_STUB_DAEMON_LINE "\n",
                           build_fingerprint,
                           socket_name,
                           pid);
    write_all(fd, hello, strlen(hello));
}

static void
stub_daemon_setup(void* data)
{
    SCOPED_RESLIST(rl);

    const char* socket_name = data;
    int socket_name_file =
        xopen(make_daemon_socket_name_file_name(), O_WRONLY | O_CREAT, 0600);
    xflock(socket_name_file, LOCK_EX);
    xftruncate(socket_name_file, 0);
    xflock(socket_name_file, LOCK_UN);
    write_all(socket_name_file, socket_name, strlen(socket_name));
    write_daemon_hello(STDOUT_FILENO, socket_name, (unsigned) getpid());
}

static void
handle_control_connection_2(int control_fd,
                            const char* socket_name,
                            bool* should_return,
                            enum stub_daemon_action* action)
{
    dbg("got control socket connection %d", control_fd);
    char command;
    if (read_all(control_fd, &command, sizeof (command))
        != sizeof (command))
    {
        android_msg(ANDROID_LOG_DEBUG,
                    "could not read command on control connection");
        return;
    }

    dbg("control socket command %c", command);

    if (command == DAEMON_COMMAND_KILL_SELF) {
        // Exit even if the write_all below fails
        *action = STUB_DAEMON_EXIT_PROGRAM;
        *should_return = true;
        android_msg(ANDROID_LOG_INFO, "fb-adb daemon exiting as requested");
        char reply = DAEMON_REPLY_OKAY;
        write_all(control_fd, &reply, sizeof (reply));
        return;
    }

    if (command == DAEMON_COMMAND_PING) {
        write_daemon_hello(control_fd, socket_name, (unsigned) getpid());
        return;
    }

    android_msg(ANDROID_LOG_WARN, "unknown control command %d", command);
}

struct handle_control_connection_ctx {
    int control_fd;
    const char* socket_name;
    enum stub_daemon_action* action;
    bool should_return;
};

static void
handle_control_connection_1(void* data)
{
    struct handle_control_connection_ctx* ctx = data;
    handle_control_connection_2(ctx->control_fd,
                                ctx->socket_name,
                                &ctx->should_return,
                                ctx->action);
}

static bool
handle_control_connection(int control_fd,
                          const char* socket_name,
                          enum stub_daemon_action* action)
{
    struct handle_control_connection_ctx ctx = {
        .control_fd = control_fd,
        .socket_name = socket_name,
        .action = action,
    };

    struct errinfo ei = ERRINFO_WANT_MSG_IF_DEBUG;
    if (catch_error(handle_control_connection_1, &ctx, &ei))
        dbg("error handling control connection:%d: %s", ei.err, ei.msg);
    return ctx.should_return;
}

static void
read_current_daemon_hello(struct daemon_hello* dhello)
{
    SCOPED_RESLIST(rl);
    int control_connection = connect_to_daemon_control();
    char command = DAEMON_COMMAND_PING;
    write_all(control_connection, &command, sizeof (command));
    if (!parse_daemon_hello(slurp_fd(control_connection, NULL),
                            dhello))
        die(ECOMM, "invalid server hello");
}

static void
try_read_current_daemon_hello_1(void* data)
{
    return read_current_daemon_hello((struct daemon_hello*) data);
}

static bool
try_reuse_current_daemon(void)
{
    struct errinfo ei = ERRINFO_WANT_MSG_IF_DEBUG;
    struct daemon_hello dhello;
    if (catch_error(try_read_current_daemon_hello_1, &dhello, &ei)) {
        dbg("could not read server hello: %d: %s", ei.err, ei.msg);
        return false;
    }

    dbg("hello from current daemon: ver:[%s] socket_name:[%s]",
        dhello.ver, dhello.socket_name);

    if (strcmp(dhello.ver, build_fingerprint) != 0) {
        dbg("daemon fingerprint mismatch: cannot reuse");
        return false;
    }

    dbg("current daemon is compatible: forwarding its credentials");
    write_daemon_hello(STDOUT_FILENO, dhello.socket_name, dhello.pid);
    return true;
}


static void
daemon_sigchild_sigaction(int signum, siginfo_t* info, void* context)
{
    (void) waitpid(-1, NULL, WNOHANG);
}

enum stub_daemon_action
run_stub_daemon(struct stub_daemon_info info)
{
    SCOPED_RESLIST(rl);

    // By default, we reuse running daemons when possible instead of
    // replacing them.  To tell whether we can reuse a currently
    // running daemon, we connect to its control socket and ask it to
    // spit out its hello line.  If the fingerprint in this line
    // matches our own, we can reuse this daemon.  Otherwise, we have
    // to replace it.  (We try to make sure we only have one daemon
    // around at a time.)
    //
    // Why not just connect to the fb-adb socket and read fb-adb
    // stub's hello line? If we do that and immediately disconnect,
    // fb-adb stub will log an error indicating that it saw an
    // unexpected EOF.  We could work around that problem and try to
    // suppress the error by writing some kind of MSG_PLEASE_DIE_NOW
    // over the fb-adb protocol, but the fb-adb protocol isn't stable
    // between versions, so we wouldn't know what bytes mean
    // MSG_PLEASE_DIE_NOW for whatever version of fb-adb we're talking
    // to.  The much simpler control socket protocol _is_ stable, so
    // we do daemon status checks over that one.
    //
    // Besides, the daemon hello line gives us the daemon's pid and
    // the stub one does not.
    //

    if (info.daemonize && !info.replace) {
        dbg("trying to reuse current daemon");
        if (try_reuse_current_daemon()) {
            return STUB_DAEMON_EXIT_PROGRAM;
        }

        dbg("no current daemon or daemon incompatible; replacing");
        info.replace = true;
    }

    if (!info.daemonize) {
        dbg("being asked not to daemonize, so replacing daemon");
        info.replace = true;
    }

    if (info.replace) {
        dbg("replacing current daemon");
        try_stop_daemon();
    }

    const char* socket_name =
        xaprintf("fb-adb-stub-%s",
                 gen_hex_random(ENOUGH_ENTROPY));

    const char* control_socket_name =
        xaprintf("%s%s", socket_name, DAEMON_CONTROL_SUFFIX);

    dbg("starting daemon: stub socket:[%s] control socket:[%s]",
        socket_name, control_socket_name);

    int listening_socket = xsocket(AF_UNIX, SOCK_STREAM, 0);
    xbind(listening_socket, make_addr_unix_abstract_s(socket_name));
    xlisten(listening_socket, 5);

    int control_socket = xsocket(AF_UNIX, SOCK_STREAM, 0);
    xbind(control_socket, make_addr_unix_abstract_s(control_socket_name));
    xlisten(control_socket, 1);

    struct pollfd pollfds[] = {
        { listening_socket, POLLIN, 0 },
        { control_socket, POLLIN, 0 },
    };

    for (unsigned i = 0; i < ARRAYSIZE(pollfds); ++i)
        fd_set_blocking_mode(pollfds[i].fd, non_blocking);

    if (info.daemonize)
        become_daemon(stub_daemon_setup, (void*) socket_name);
    else
        stub_daemon_setup((void*) socket_name);

    dbg("accepting connections");

    struct sigaction sa = {
        .sa_sigaction = daemon_sigchild_sigaction,
        .sa_flags = SA_SIGINFO,
    };
    sigaction_restore_as_cleanup(SIGCHLD, &sa);
    save_signals_unblock_for_io();
    sigaddset(&signals_unblock_for_io, SIGCHLD);

    for (;;) {
        SCOPED_RESLIST(rl_accept);
        int pollret = xpoll(pollfds, ARRAYSIZE(pollfds), DAEMON_TIMEOUT_MS);
        if (pollret == 0) {
            android_msg(ANDROID_LOG_INFO,
                        "fb-adb daemon timed out; exiting");
            return STUB_DAEMON_EXIT_PROGRAM;
        }

        int control_connection;
        if (pollfds[1].revents &&
            (control_connection = xaccept_nonblock(control_socket)) != -1)
        {
            enum stub_daemon_action action;
            if (handle_control_connection(control_connection,
                                          socket_name,
                                          &action))
                return action;
            continue;
        }

        int client_connection;
        if (pollfds[0].revents &&
            (client_connection = xaccept_nonblock(listening_socket)))
        {
            pid_t child = fork();
            if (child == (pid_t) -1) {
                android_msg(ANDROID_LOG_WARN,
                            "fork failed: %s",
                            strerror(errno));
                continue;
            }

            if (child == 0) {
                xdup3nc(client_connection, STDIN_FILENO, 0);
                xdup3nc(client_connection, STDOUT_FILENO, 0);
                return STUB_DAEMON_RUN_STUB;
            }
        }
    }
}
