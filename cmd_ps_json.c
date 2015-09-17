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
#include "json.h"

#if FBADB_MAIN

FORWARD(ps_json);

#elif !defined(__linux__)

int
ps_json_main(const struct cmd_ps_json_info* info)
{
    die(EINVAL, "this command is supported only on Linux");
}

#else

static size_t
slurp_pids_1(DIR* procdir, uint32_t* pid_list, size_t pid_list_size)
{
    rewinddir(procdir);
    size_t nr_pids = 0;
    struct dirent* ent;
    while ((ent = readdir(procdir)) != NULL) {
        char* endptr = NULL;
        errno = 0;
        unsigned long raw_pid = strtoul(ent->d_name, &endptr, 10);
        if (raw_pid == 0 || errno != 0 || *endptr != '\0')
            continue;
        if (nr_pids < pid_list_size)
            pid_list[nr_pids] = raw_pid;
        nr_pids += 1;
    }

    return nr_pids;
}

static void
slurp_pids(DIR* procdir, uint32_t** pids_out, size_t* nr_out)
{
    struct cleanup* pids_cl = NULL;
    uint32_t* pids = NULL;
    size_t nr_pids = 0;
    size_t found_pids = 32;

    do {
        nr_pids = found_pids;
        if (nr_pids >= SIZE_MAX / sizeof (pids[0]))
            die_oom();
        struct cleanup* new_pids_cl = cleanup_allocate();
        uint32_t* new_pids = resize_alloc(pids, nr_pids * sizeof (pids[0]));
        if (new_pids == NULL)
            die_oom();
        cleanup_forget(pids_cl);
        cleanup_commit(new_pids_cl, free, new_pids);
        pids_cl = new_pids_cl;
        pids = new_pids;
        found_pids = slurp_pids_1(procdir, pids, nr_pids);
    } while (found_pids > nr_pids);

    *pids_out = pids;
    *nr_out = found_pids;
}

static int
compar_pids(const void* ap, const void* bp)
{
    uint32_t a, b;
    memcpy(&a, ap, sizeof (a));
    memcpy(&b, bp, sizeof (b));
    return (a < b) ? -1 : a != b;
}

struct pid_field {
    const char* name;
    void (*emit)(struct json_writer*, uint32_t pid);
};

static void
pid_emit_cmdline(struct json_writer* writer, uint32_t pid)
{
    int cmdline_file =
        xopen(xaprintf("/proc/%u/cmdline", pid), O_RDONLY, 0);
    size_t cmdlinesz;
    char* cmdline = slurp_fd(cmdline_file, &cmdlinesz);
    char* cmdline_end = cmdline + cmdlinesz;
    json_begin_array(writer);
    while (cmdline < cmdline_end) {
        json_emit_string(writer, cmdline);
        cmdline += strlen(cmdline) + 1;
    }
    json_end_array(writer);
}

static void
pid_emit_environ(struct json_writer* writer, uint32_t pid)
{
    int environ_file =
        xopen(xaprintf("/proc/%u/environ", pid), O_RDONLY, 0);
    size_t environsz;
    char* environ = slurp_fd(environ_file, &environsz);
    char* environ_end = environ + environsz;
    json_begin_array(writer);
    while (environ < environ_end) {
        json_emit_string(writer, environ);
        environ += strlen(environ) + 1;
    }
    json_end_array(writer);
}

static const struct pid_field pid_fields[] = {
    { "cmdline", pid_emit_cmdline },
    { "environ", pid_emit_environ },
};

struct emit_field_ctx {
    struct json_writer* writer;
    uint32_t pid;
    const struct pid_field* field;
};

static void
emit_pid_field_1(void* data)
{
    struct emit_field_ctx* ctx = data;
    ctx->field->emit(ctx->writer, ctx->pid);
}

static void
emit_pid_field(struct json_writer* writer,
               uint32_t pid,
               const struct pid_field* field)
{
    json_begin_field(writer, field->name);
    json_begin_object(writer);
    const struct json_context* savedc = json_save_context(writer);
    json_begin_field(writer, "value");
    struct emit_field_ctx ctx = {
        .writer = writer,
        .pid = pid,
        .field = field,
    };

    struct errinfo ei = {
        .want_msg = true
    };

    bool error = catch_error(emit_pid_field_1, &ctx, &ei);
    json_pop_to_saved_context(writer, savedc);

    if (error) {
        json_begin_field(writer, "error");
        json_emit_string(writer, ei.msg);
    }

    json_end_object(writer);
}

int
ps_json_main(const struct cmd_ps_json_info* info)
{
    DIR* procdir = xopendir("/proc");
    uint32_t* pids;
    size_t nr_pids;
    struct json_writer* writer = json_writer_create(xstdout);

    json_begin_array(writer);

    slurp_pids(procdir, &pids, &nr_pids);
    qsort(pids, nr_pids, sizeof (pids[0]), compar_pids);

    for (size_t i = 0; i < nr_pids; ++i) {
        json_begin_object(writer);
        json_begin_field(writer, "pid");
        json_emit_u64(writer, pids[i]);
        for (size_t j = 0; j < ARRAYSIZE(pid_fields); ++j) {
            emit_pid_field(writer, pids[i], &pid_fields[j]);
        }
        json_end_object(writer);
    }

    json_end_array(writer);
    return 0;
}

#endif
