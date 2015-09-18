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
#include "util.h"
#include "autocmd.h"
#include "fs.h"
#include "child.h"
#include "constants.h"

FORWARD(rdex);

#if !FBADB_MAIN

static char*
make_odex_name(const char* dex_file_name)
{
    char* dex_file_name_copy = xstrdup(dex_file_name);
    char* suffix = strrchr(dex_file_name_copy, '.');
    if (suffix == NULL || strcmp(suffix, ".jar") != 0)
        die(EINVAL, "invalid .jar file name %s", dex_file_name);

    *suffix = '\0';
    return xaprintf("%s.odex", dex_file_name_copy);
}

static void
cleanup_tmpfile(void* data)
{
    (void) unlink((const char*) data);
}

static void
compile_dex_with_dexopt(const char* dex_file_name,
                        const char* odex_file_name)
{
    SCOPED_RESLIST(rl);

    int dex_file = xopen(dex_file_name, O_RDONLY, 0);
    const char* odex_temp_filename = xaprintf(
        "%s.tmp.%s",
        odex_file_name,
        gen_hex_random(ENOUGH_ENTROPY));
    cleanup_commit(cleanup_allocate(), cleanup_tmpfile, odex_temp_filename);
    int odex_temp_file = xopen(odex_temp_filename,
                               O_RDWR | O_CREAT | O_EXCL,
                               0644);

    allow_inherit(dex_file);
    allow_inherit(odex_temp_file);

    struct child_start_info csi = {
        .io[0] = CHILD_IO_DEV_NULL,
        .io[1] = CHILD_IO_PIPE,
        .io[2] = CHILD_IO_DUP_TO_STDOUT,
        .exename = "dexopt",
        .argv = ARGV(
            "dexopt",
            "--zip",
            xaprintf("%d", dex_file),
            xaprintf("%d", odex_temp_file),
            dex_file_name,
            "v=ao=fm=y"),
    };

    struct child* dexopt = child_start(&csi);
    struct growable_buffer output = slurp_fd_buf(dexopt->fd[1]->fd);
    int status = child_status_to_exit_code(child_wait(dexopt));
    if (status != 0)
        die(EINVAL,
            "dexopt failed: %s",
            massage_output_buf(output));

    xrename(odex_temp_filename, odex_file_name);
}

static void
compile_dex(const char* dex_file_name,
            const char* odex_file_name)
{
    if (api_level() < 21)
        compile_dex_with_dexopt(dex_file_name, odex_file_name);
}

int
rdex_main(const struct cmd_rdex_info* info)
{
    const char* dex_file_name = info->dexfile;
    struct stat dex_stat = xstat(dex_file_name);
    const char* odex_file_name = make_odex_name(dex_file_name);

    bool need_recompile = true;

    struct stat odex_stat;
    if (stat(odex_file_name, &odex_stat) == 0 &&
        dex_stat.st_mtime <= odex_stat.st_mtime)
    {
        need_recompile = false;
    }

    (void) need_recompile;
    (void) odex_file_name;
    (void) compile_dex;

    if (need_recompile)
        compile_dex(dex_file_name, odex_file_name);

    if (setenv("CLASSPATH", dex_file_name, 1) == -1)
        die_errno("setenv");

    execvp("app_process",
           (char* const*)
           ARGV_CONCAT(
               ARGV("app_process",
                    xdirname(dex_file_name),
                    info->classname),
               info->args ?: empty_argv));
    die_errno("execvp(\"app_process\", ...");
}
#endif
