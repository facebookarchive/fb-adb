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
#pragma once
#include <stdint.h>
#pragma pack(push, 1)

/* The world is little-endian */

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
# error "fb-adb is not ported to big-endian systems"
#endif

#define ENUM_MSG_TYPES(_m)                         \
    _m(MSG_CHANNEL_DATA)                           \
    _m(MSG_CHANNEL_DATA_LZ4)                       \
    _m(MSG_CHANNEL_WINDOW)                         \
    _m(MSG_CHANNEL_CLOSE)                          \
    _m(MSG_CHILD_EXIT)                             \
    _m(MSG_ERROR)                                  \
    _m(MSG_WINDOW_SIZE)                            \
    _m(MSG_SHEX_HELLO)                             \
    _m(MSG_CMDLINE_ARGUMENT)                       \
    _m(MSG_CMDLINE_ARGUMENT_JUMBO)                 \
    _m(MSG_CLEARENV)                               \
    _m(MSG_ENVIRONMENT_VARIABLE_SET)               \
    _m(MSG_ENVIRONMENT_VARIABLE_UNSET)             \
    _m(MSG_ENVIRONMENT_VARIABLE_SET_JUMBO)         \
    _m(MSG_ENVIRONMENT_VARIABLE_UNSET_JUMBO)       \
    _m(MSG_CMDLINE_DEFAULT_SH)                     \
    _m(MSG_CMDLINE_DEFAULT_SH_LOGIN)               \
    _m(MSG_EXEC_AS_ROOT)                           \
    _m(MSG_EXEC_AS_USER)                           \
    _m(MSG_CHDIR)                                  \
    _m(MSG_REBIND_TO_UNIX_SOCKET)                  \
    _m(MSG_REBIND_TO_TCP4_SOCKET)                  \
    _m(MSG_REBIND_TO_TCP6_SOCKET)                  \
    _m(MSG_LISTENING_ON_SOCKET)

enum msg_type {
    MSG_TYPE_PRE = 39, // Make sure zero is not a valid message
#define M(_name) _name,
    ENUM_MSG_TYPES(M)
#undef M
};

#define MSG_MAX_SIZE UINT16_MAX

struct msg {
    uint16_t size;
    uint16_t type;
};

struct msg_channel_data {
    struct msg msg;
    uint8_t channel;
    char data[0];
};

struct msg_channel_data_lz4 {
    struct msg msg;
    uint16_t uncompressed_size;
    uint8_t channel;
    char data[0];
};

struct msg_channel_window {
    struct msg msg;
    uint32_t window_delta;
    uint8_t channel;
};

struct msg_channel_close {
    struct msg msg;
    uint8_t channel;
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
    unsigned compress : 1;
};

struct msg_shex_hello {
    struct msg msg;
    uint64_t version;
    uint32_t stub_recv_bufsz;
    uint32_t stub_send_bufsz;
    uint32_t nr_argv;
    uint32_t ispeed;
    uint32_t ospeed;
    uint16_t maxmsg;
    struct window_size ws;
    uint8_t have_ws;
    uint8_t posix_vdisable_value;
    uint8_t stdio_socket_p;
    uint8_t ctty_p;
    struct stream_information si[3];
    struct term_control tctl[0]; // Must be last
};

struct msg_cmdline_argument {
    struct msg msg;
    char value[0];
};

struct msg_cmdline_argument_jumbo {
    struct msg msg;
    uint32_t actual_size;
    // Large argument follows.
};

struct msg_environment_variable_set {
    struct msg msg;
    char value[0]; // NUL separates name and value.
};

struct msg_environment_variable_set_jumbo {
    struct msg msg;
    uint32_t name_length;
    uint32_t value_length;
};

struct msg_environment_variable_unset {
    struct msg msg;
    char name[0];
};

struct msg_environment_variable_unset_jumbo {
    struct msg msg;
    uint32_t name_length;
    // Name follows
};

struct msg_exec_as_user {
    struct msg msg;
    uint8_t shell_thunk;
    char username[0];
};

struct msg_chdir {
    struct msg msg;
    char dir[0];
};

struct msg_rebind_to_unix_socket {
    struct msg msg;
    char socket[0];
};

struct msg_rebind_to_tcp4_socket {
    struct msg msg;
    uint16_t port;
    uint32_t addr; // Like in_addr
};

struct msg_rebind_to_tcp6_socket {
    struct msg msg;
    uint16_t port;
    uint8_t addr[16]; // Like in6_addr
};

#pragma pack(pop)

static const unsigned CHILD_STDIN = 2;
static const unsigned CHILD_STDOUT = 3;
static const unsigned CHILD_STDERR = 4;

#define FB_ADB_PROTO_START_LINE "FB_ADB %ju (uid=%d) (api=%u)"
