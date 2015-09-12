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
    const char* service_sockname =
        xaprintf("fb-adb-service-%s",
                 gen_hex_random(ENOUGH_ENTROPY));
    int service_listen_fd = xsocket(AF_UNIX, SOCK_STREAM, 0);
    xbind(service_listen_fd,
          make_addr_unix_abstract(service_sockname,
                                  strlen(service_sockname)));
    xlisten(service_listen_fd, 1);

    struct child_start_info csi = {
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
        .flags = (CHILD_NULL_STDIN |
                  CHILD_MERGE_STDERR),
    };

    struct child* am = child_start(&csi);
    // am doesn't use exit status to indicate that it worked, so look
    // for the success string in its output.

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

    set_timeout_ms(timeout_ms,
                   ETIMEDOUT,
                   "timeout waiting for service callback");
    WITH_CURRENT_RESLIST(rl->parent);
    return xaccept(service_listen_fd);
}

void
start_daemon_via_service_hack(const char* package_name)
{
    SCOPED_RESLIST(rl);

    int peer_fd = fb_adb_service_connect(package_name, 1000);

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
        "exec ./.fb-adb stub -ldr"

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
            if (printf("%s\n", line) == -1)
                die_errno("printf");
            if (fflush(stdout) == -1)
                die_errno("fflush");
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
    struct errinfo ei = {
#ifndef NDEBUG
        .want_msg = true,
#endif
    };

    if (catch_error(try_stop_daemon_1, NULL, &ei))
        dbg("failed to stop daemon: %s", ei.msg);
    else
        dbg("stopped running daemon");
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

    if (printf(FB_ADB_STUB_DAEMON_LINE "\n",
               build_fingerprint,
               socket_name,
               (unsigned) getpid()) < 0)
        die_errno("printf");
    if (fflush(stdout) == -1)
        die_errno("flush");
}

static void
write_command_reply(int fd, char c)
{
    ssize_t ret;
    do {
        WITH_IO_SIGNALS_ALLOWED();
        ret = write(fd, &c, sizeof (c));
    } while (ret == -1 && errno == EINTR);
}

enum stub_daemon_action
run_stub_daemon(struct stub_daemon_info info)
{
    SCOPED_RESLIST(rl);

    if (info.replace)
        try_stop_daemon();

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
            char command;
            if (read_all(control_connection, &command, sizeof (command))
                != sizeof (command))
            {
                android_msg(ANDROID_LOG_DEBUG,
                            "could not read command on control connection");
                continue;
            }

            if (command == DAEMON_COMMAND_KILL_SELF) {
                write_command_reply(control_connection, DAEMON_REPLY_OKAY);
                android_msg(ANDROID_LOG_INFO,
                            "fb-adb daemon exiting as requested");
                return STUB_DAEMON_EXIT_PROGRAM;
            }

            if (command == DAEMON_COMMAND_PING)
                write_command_reply(control_connection, DAEMON_REPLY_OKAY);
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
