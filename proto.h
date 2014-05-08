#pragma once
#include <stdint.h>

enum msg_type {
    MSG_CHANNEL_DATA = 40,
    MSG_CHANNEL_WINDOW,
    MSG_CHANNEL_CLOSE,
    MSG_CHILD_EXIT,
    MSG_ERROR,
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

static const unsigned CHILD_STDIN = 2;
static const unsigned CHILD_STDOUT = 3;
static const unsigned CHILD_STDERR = 4;

#define XXX_BUFSZ 32
