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
#include <ctype.h>
#include <limits.h>
#include <arpa/inet.h>
#include <string.h>
#include "util.h"
#include "autocmd.h"
#include "fs.h"
#include "child.h"
#include "net.h"
#include "strutil.h"
#include "constants.h"
#include "core.h"

#if FBADB_MAIN

int
start_daemon_main(const struct cmd_start_daemon_info* info)
{
    start_fb_adb_service(&info->adb, info->package);
    return 0;
}

#else

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
    char line[512];
    while (fgets(line, sizeof (line), am_out)) {
        if (string_starts_with_p(line, "Error: "))
            die(ECOMM,
                "starting fb-adb service for package %s failed: %s",
                package,
                line + strlen("Error: "));
    }

    if (ferror(am_out))
        die_errno("fgets");

    set_timeout_ms(timeout_ms,
                   ETIMEDOUT,
                   "timeout waiting for service callback");
    WITH_CURRENT_RESLIST(rl->parent);
    return xaccept(service_listen_fd);
}

int
start_daemon_main(const struct cmd_start_daemon_info* info)
{
    SCOPED_RESLIST(rl);

    int peer_fd = fb_adb_service_connect(info->package, 1000);

#define SCRIPT_TEMPLATE                                              \
    "set -e -- %s \".fb-adb.tmp.$$\"; "                              \
    "if ! /system/bin/cmp .fb-adb \"$1\" >/dev/null 2>&1; then "     \
        "  /system/bin/cat \"$1\" > \"$2\"; "                        \
        "  if ! /system/bin/chmod 555 \"$2\" || "                    \
        "     ! " MV_F " \"$2\" .fb-adb; then "                      \
        "    " RM_F " \"$2\" || true; "                              \
        "    exit 1;"                                                \
        "  fi; "                                                     \
        "fi; "                                                       \
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

    int exit_status = 1;
    FILE* from_peer = xfdopen(peer_fd, "r");
    char line[512];
    while (fgets(line, sizeof (line), from_peer)) {
        struct daemon_hello dhello;
        if (parse_daemon_hello(line, &dhello)) {
            if (printf("%s", line) == -1)
                die_errno("printf");
            if (fflush(stdout) == -1)
                die_errno("fflush");
            exit_status = 0;
        }
    }

    if (ferror(from_peer))
        die_errno("fgets");

    return exit_status;
}

#endif
