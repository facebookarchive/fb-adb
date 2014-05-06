#pragma once
#include <stdint.h>

enum msg_type {
    MSG_CHANNEL_DATA,
    MSG_CHANNEL_WINDOW,
    MSG_CHANNEL_CLOSE,
    MSG_CHILD_EXIT,
    MSG_ERROR,
};

struct msg {
    uint8_t type;
    uint16_t size;
};

struct msg_channel_data {
    struct msg msg;
    uint8_t channel;
    char data[0];
};

struct msg_channel_window {
    struct msg msg;
    uint8_t channel;
    uint32_t window_delta;
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

union msg_all {
    struct msg msg;
    struct msg_channel_data data;
    struct msg_channel_window window;
    struct msg_channel_close close;
    struct msg_error error;
    struct msg_child_exit exit;
};

static const unsigned CHILD_STDIN = 2;
static const unsigned CHILD_STDOUT = 3;
static const unsigned CHILD_STDERR = 4;
