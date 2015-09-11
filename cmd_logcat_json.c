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
#include <time.h>
#include "util.h"
#include "autocmd.h"
#include "child.h"
#include "fs.h"
#include "json.h"

// ------------- FROM AOSP ------------

/*
 * The maximum size of the log entry payload that can be
 * written to the logger. An attempt to write more than
 * this amount will result in a truncated log entry.
 */
#define LOGGER_ENTRY_MAX_PAYLOAD	4076

/*
 * The userspace structure for version 1 of the logger_entry ABI.
 * This structure is returned to userspace by the kernel logger
 * driver unless an upgrade to a newer ABI version is requested.
 */
struct logger_entry {
    uint16_t    len;    /* length of the payload */
    uint16_t    __pad;  /* no matter what, we get 2 bytes of padding */
    int32_t     pid;    /* generating process's pid */
    int32_t     tid;    /* generating process's tid */
    int32_t     sec;    /* seconds since Epoch */
    int32_t     nsec;   /* nanoseconds */
    char        msg[0]; /* the entry's payload */
} __attribute__((__packed__));

/*
 * The userspace structure for version 2 of the logger_entry ABI.
 * This structure is returned to userspace if ioctl(LOGGER_SET_VERSION)
 * is called with version==2; or used with the user space log daemon.
 */
struct logger_entry_v2 {
    uint16_t    len;       /* length of the payload */
    uint16_t    hdr_size;  /* sizeof(struct logger_entry_v2) */
    int32_t     pid;       /* generating process's pid */
    int32_t     tid;       /* generating process's tid */
    int32_t     sec;       /* seconds since Epoch */
    int32_t     nsec;      /* nanoseconds */
    uint32_t    euid;      /* effective UID of logger */
    char        msg[0];    /* the entry's payload */
} __attribute__((__packed__));

struct logger_entry_v3 {
    uint16_t    len;       /* length of the payload */
    uint16_t    hdr_size;  /* sizeof(struct logger_entry_v3) */
    int32_t     pid;       /* generating process's pid */
    int32_t     tid;       /* generating process's tid */
    int32_t     sec;       /* seconds since Epoch */
    int32_t     nsec;      /* nanoseconds */
    uint32_t    lid;       /* log id of the payload */
    char        msg[0];    /* the entry's payload */
} __attribute__((__packed__));

// ----------- END AOSP -----------

static void
read_all_or_die(int fd, void* buf, size_t sz)
{
    size_t nr_read = read_all(fd, buf, sz);
    if (nr_read != sz)
        die(ENOTBLK, "unexpected EOF from inferior logcat");
}

union logent {
    struct logger_entry v1;
    struct logger_entry_v2 v2;
    struct logger_entry_v3 v3;
};

static const char*
logcat_priority_name(uint8_t priority)
{
    switch (priority) {
        case 2: return "verbose";
        case 3: return "debug";
        case 4: return "info";
        case 5: return "warn";
        case 6: return "error";
        case 7: return "fatal";
        default: return "?";
    }
}

static void
read_and_dump_log_entry(int logcat_fd,
                        unsigned api_level,
                        bool gmt,
                        const char* time_format)
{
    SCOPED_RESLIST(rl);

    union logent hdr;
    union logent* le;
    size_t hdrsz;
    size_t payloadsz;

    read_all_or_die(logcat_fd, &hdr.v1, sizeof (hdr.v1));
    if (api_level < 21) {
        payloadsz = hdr.v1.len;
        hdrsz = sizeof (hdr.v1);
    } else {
        payloadsz = hdr.v2.len;
        hdrsz = hdr.v2.hdr_size;
        if (hdrsz < sizeof (hdr.v1))
            die(EINVAL, "bogus packet from logcat");
    }

    le = alloca(hdrsz + payloadsz);
    memcpy(&le->v1, &hdr.v1, sizeof (hdr.v1));
    read_all_or_die(logcat_fd,
                    (uint8_t*) le + sizeof (hdr.v1),
                    hdrsz + payloadsz - sizeof (hdr.v1));
    char* payload = (char*) le + hdrsz;
    char* payload_end = payload + payloadsz;

    struct json_writer* writer = json_writer_create(stdout);
    json_begin_object(writer);
    json_begin_field(writer, "pid");
    json_emit_i64(writer, le->v1.pid);
    json_begin_field(writer, "tid");
    json_emit_i64(writer, le->v1.tid);
    json_begin_field(writer, "sec");
    json_emit_i64(writer, le->v1.sec);
    json_begin_field(writer, "nsec");
    json_emit_i64(writer, le->v1.nsec);

    if (time_format != NULL) {
        time_t time = le->v1.sec;
        struct tm* tm = (gmt ? gmtime : localtime)(&time);
        if (tm != NULL) {
            char timebuf[64];
            size_t timelen =
                strftime(timebuf,
                         sizeof (timebuf),
                         time_format,
                         tm);
            json_begin_field(writer, "time");
            json_emit_string_n(writer, timebuf, timelen);
        }
    }

    uint8_t priority;
    if (payload < payload_end) {
        priority = *payload;
        payload += 1;
    } else {
        priority = 0;
    }

    json_begin_field(writer, "priority");
    json_emit_string(writer, logcat_priority_name(priority));

    size_t tag_length = strnlen(payload, payload_end - payload);
    json_begin_field(writer, "tag");
    json_emit_string_n(writer, payload, tag_length);
    payload += tag_length;
    if (payload < payload_end)
        payload += 1;

    size_t message_length = strnlen(payload, payload_end - payload);
    json_begin_field(writer, "message");
    json_emit_string_n(writer, payload, message_length);
    json_end_object(writer);
    xputc('\n', stdout);
    xflush(stdout);
}

int
logcat_json_main(const struct cmd_logcat_json_info* info)
{
    struct cmd_shell_info shcmdi = {
        .adb = info->adb,
        .transport = info->transport,
        .user = info->user,
        .command = "getprop ro.build.version.sdk&&exec logcat -B"
    };

    struct strlist* args = strlist_new();
    strlist_append(args, orig_argv0);
    strlist_append(args, "shell");
    strlist_xfer(args, make_args_cmd_shell(CMD_ARG_FORWARDED, &shcmdi));

    struct child_start_info csi = {
        .flags = (CHILD_NULL_STDIN | CHILD_INHERIT_STDERR),
        .exename = my_exe(),
        .argv = strlist_to_argv(args),
    };

    struct child* captive_logcat = child_start(&csi);
    int logcat_fd = captive_logcat->fd[1]->fd;
    unsigned api_level = 0;

    for (;;) {
        char c;
        if (read_all(logcat_fd, &c, 1) < 1)
            die(ECOMM, "invalid API level");
        if ('0' <= c && c <= '9')
            api_level = api_level * 10 + (c - '0');
        else if (c == '\n')
            break;
        else
            die(ECOMM, "invalid API level");
    }

    if (api_level == 0)
        die(ECOMM, "invalid API level");

    const char* time_format = "%a, %d %b %Y %H:%M:%S";
    if (info->logcat_json.time_format)
        time_format = info->logcat_json.time_format;
    bool gmt = info->logcat_json.gmt;

    for (;;) {
        read_and_dump_log_entry(
            logcat_fd,
            api_level,
            gmt,
            time_format);
    }
}
