/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once
#include <stdint.h>

/* The world is little-endian */

enum msg_type {
    MSG_CHANNEL_DATA = 40,
    MSG_CHANNEL_WINDOW,
    MSG_CHANNEL_CLOSE,
    MSG_CHILD_EXIT,
    MSG_ERROR,
    MSG_WINDOW_SIZE,
    MSG_SHEX_HELLO,
    MSG_CMDLINE_ARGUMENT,
    MSG_CMDLINE_DEFAULT_SH,
    MSG_CMDLINE_DEFAULT_SH_LOGIN,
    MSG_EXEC_AS_ROOT,
};

struct msg {
    uint16_t size;
    uint16_t type;
};

struct msg_channel_data {
    struct msg msg;
    uint32_t channel;
    char data[0];
};

struct msg_channel_window {
    struct msg msg;
    uint32_t channel;
    uint32_t window_delta;
};

struct msg_channel_close {
    struct msg msg;
    uint32_t channel;
};

struct msg_error {
    struct msg msg;
    char text[0];
};

struct msg_child_exit {
    struct msg msg;
    uint8_t exit_status;
};

struct window_size {
    uint16_t row;
    uint16_t col;
    uint16_t xpixel;
    uint16_t ypixel;
};

struct msg_window_size {
    struct msg msg;
    struct window_size ws;
};

struct term_control {
    uint8_t value;
    char name[9];
};

struct stream_information {
    uint32_t bufsz;
    unsigned pty_p : 1;
};

struct msg_shex_hello {
    struct msg msg;
    uint64_t version;
    uint32_t maxmsg;
    uint32_t stub_recv_bufsz;
    uint32_t stub_send_bufsz;
    uint32_t nr_argv;
    uint8_t have_ws;
    struct window_size ws;
    uint32_t ispeed;
    uint32_t ospeed;
    uint8_t posix_vdisable_value;
    struct stream_information si[3];
    struct term_control tctl[0];
};

struct msg_cmdline_argument {
    struct msg msg;
    char value[0];
};

static const unsigned CHILD_STDIN = 2;
static const unsigned CHILD_STDOUT = 3;
static const unsigned CHILD_STDERR = 4;

#define FB_ADB_PROTO_START_LINE "FB_ADB protocol %ju follows (uid=%d)"
