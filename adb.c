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
#include <stdlib.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include "adb.h"
#include "child.h"
#include "util.h"
#include "argv.h"
#include "strutil.h"

void
adb_send_file(const char* local,
              const char* remote,
              const char* const* adb_args)
{
    SCOPED_RESLIST(rl_send_stub);

    struct child_start_info csi = {
        .flags = CHILD_MERGE_STDERR,
        .exename = "adb",
        .argv = argv_concat((const char*[]){"adb", NULL},
                            adb_args ?: empty_argv,
                            (const char*[]){"push", local, remote, NULL},
                            NULL),
    };
    struct child* adb = child_start(&csi);
    fdh_destroy(adb->fd[0]);

    char buf[512];
    size_t len = read_all(adb->fd[1]->fd, buf, sizeof (buf));
    fdh_destroy(adb->fd[1]);

    int status = child_wait(adb);
    if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
        if (len == sizeof (buf))
            --len;

        while (len > 0 && isspace(buf[len - 1]))
            --len;

        buf[len] = '\0';

        char* epos = buf;
        while (*epos != '\0' && isspace(*epos))
            ++epos;

        if (strncmp(epos, "error: ", strlen("error: ")) == 0) {
            epos += strlen("error: ");
            char* e = strchr(epos, '\n');
            if (e) *e = '\0';
        }

        die(ECOMM, "adb error: %s", epos);
    }
}

void adb_rename_file(const char* old_name,
                     const char* new_name,
                     const char* const* adb_args)
{
    if (!shell_safe_word_p(old_name))
        die(EINVAL, "invalid shell word: [%s]", old_name);

    if (!shell_safe_word_p(new_name))
        die(EINVAL, "invalid shell word: [%s]", new_name);

    const struct child_start_info csi = {
        .flags = CHILD_NULL_STDIN | CHILD_MERGE_STDERR,
        .exename = "adb",
        .argv = argv_concat((const char*[]){"adb", NULL},
                            adb_args,
                            (const char*[]){"shell",
                                    "mv",
                                    old_name,
                                    new_name,
                                    "&&",
                                    "echo",
                                    "yes",
                                    NULL},
                            NULL),
    };

    struct child* child = child_start(&csi);
    char buf[256];
    buf[0] = '\0';
    size_t len = read_all(child->fd[1]->fd, buf, sizeof (buf)-1);
    fdh_destroy(child->fd[1]);
    (void) child_wait(child);
    buf[len] = '\0';
    if (strcmp(buf, "yes\r\n") != 0) {
        while (len > 0 && isspace(buf[len - 1]))
            --len;

        die(ECOMM, "moving fb-adb to final location failed: %s", buf);
    }
}
