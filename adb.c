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
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include "adb.h"
#include "child.h"
#include "util.h"
#include "argv.h"
#include "strutil.h"

static char*
output2str(struct child_communication* com)
{
    return massage_output(com->out[0].bytes, com->out[0].nr);
}

static struct child_communication*
run_adb(const char* const* adb_args,
        const char* args[])
{
    struct child_start_info csi = {
        .flags = CHILD_MERGE_STDERR,
        .exename = "adb",
        .argv = ARGV_CONCAT(ARGV("adb"),
                            adb_args ?: empty_argv,
                            args ?: empty_argv)
    };

    return child_communicate(child_start(&csi), NULL, 0);
}

void
adb_send_file(const char* local,
              const char* remote,
              const char* const* adb_args)
{
    SCOPED_RESLIST(rl);

    struct child_communication* com =
        run_adb(adb_args, ARGV("push", local, remote));

    if (!child_status_success_p(com->status))
        die(ECOMM, "adb error: %s", output2str(com));
}

void
adb_rename_file(const char* old_name,
                const char* new_name,
                unsigned api_level,
                const char* const* adb_args)
{
    SCOPED_RESLIST(rl);

    if (!shell_safe_word_p(old_name))
        die(EINVAL, "invalid shell word: [%s]", old_name);

    if (!shell_safe_word_p(new_name))
        die(EINVAL, "invalid shell word: [%s]", new_name);

    // Old versions of Android don't support mv -f, but treat stdin of
    // /dev/null as a clue to not prompt on overwrite.  Google somehow
    // managed to screw up mv(1) in API 23 and above so that the
    // </dev/null trick doesn't work for suppressing the overwrite
    // prompt --- instead, it makes mv delete(!) the source file.
    // Let's just make the move version-dependent.  Split on version
    // 19, because that version does support mv -f and we want to
    // catch all possible breakage.

    struct child_communication* com =
        run_adb(adb_args,
                api_level > 19
                ? ARGV("shell",
                       "mv",
                       "-f",
                       old_name,
                       new_name,
                       "&&",
                       "echo",
                       "yes")
                : ARGV("shell",
                       "</dev/null",
                       "mv",
                       old_name,
                       new_name,
                       "&&",
                       "echo",
                       "yes"));

    const char* output = output2str(com);
    if (!child_status_success_p(com->status) || strcmp(output, "yes") != 0)
        die(ECOMM, "moving fb-adb to final location failed: %s", output);
}

void
adb_add_forward(const char* local,
                const char* remote,
                const char* const* adb_args)
{
    struct child_communication* com =
        run_adb(adb_args, ARGV("forward", local, remote));

    if (!child_status_success_p(com->status))
        die(ECOMM, "adb_add_forward failed: %s", output2str(com));
}

void
adb_remove_forward(const char* local,
                   const char* const* adb_args)
{
    struct child_communication* com =
        run_adb(adb_args, ARGV("forward", "--remove", local));

    if (!child_status_success_p(com->status))
        die(ECOMM, "adb_remove_forward failed: %s", output2str(com));
}

struct remove_forward_cleanup {
    struct cleanup* cl;
    const char* local;
    const char* const* adb_args;
};

static void
remove_forward_cleanup_1(void* data)
{
    struct remove_forward_cleanup* crf = data;
    adb_remove_forward(crf->local, crf->adb_args);
}

static void
remove_forward_cleanup(void* data)
{
    SCOPED_RESLIST(rl);
    (void) catch_error(remove_forward_cleanup_1, data, NULL);
}

struct remove_forward_cleanup*
remove_forward_cleanup_allocate(
    const char* local,
    const char* const* adb_args)
{
    struct remove_forward_cleanup* crf = xcalloc(sizeof (*crf));
    crf->cl = cleanup_allocate();
    crf->local = xstrdup(local);
    crf->adb_args = argv_concat_deepcopy(adb_args, NULL);
    return crf;
}

void
remove_forward_cleanup_commit(struct remove_forward_cleanup* rfc)
{
    cleanup_commit(rfc->cl, remove_forward_cleanup, rfc);
}

char*
adb_getprop(const char* property, const char* const* adb_args)
{
    SCOPED_RESLIST(rl);

    struct child_communication* com = run_adb(
        adb_args,
        ARGV("shell", "getprop", property));
    char* output = output2str(com);
    if (!child_status_success_p(com->status))
        die(ECOMM, "adb error: %s", output2str(com));

    const char* ws = " \t\r\n";

    while (strchr(ws, *output))
        ++output;

    size_t output_length = strlen(output);
    while (output_length > 0 && strchr(ws, output[output_length-1]))
        output_length -= 1;

    if (output_length == 0)
        die(EINVAL, "property %s missing or empty", property);

    WITH_CURRENT_RESLIST(rl->parent);
    char* value = xstrndup(output, output_length);
    dbg("property [%s] = [%s]", property, value);
    return value;
}

unsigned
adb_api_level(const char* const* adb_args)
{
    SCOPED_RESLIST(rl);
    char* api_level_string = adb_getprop("ro.build.version.sdk", adb_args);
    char* endptr;
    errno = 0;
    unsigned long api_level = strtoul(api_level_string, &endptr, 10);
    if (*endptr != '\0' || errno != 0 || api_level > UINT_MAX)
        die(EINVAL,
            "bogus api level property value: [%s]",
            api_level_string);

    return (unsigned) api_level;
}
