// Copyright 2004-present Facebook. All Rights Reserved.
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <sys/uio.h>
#include <sys/poll.h>

enum channel_direction {
    CHANNEL_TO_FD,
    CHANNEL_FROM_FD,
};

struct channel {
    struct fdh* fdh;
    enum channel_direction dir;
    int err;
    struct ringbuf* rb;
    uint32_t bytes_written;
    uint32_t window;
    unsigned sent_eof : 1;
    unsigned pending_close : 1;
    unsigned always_buffer : 1;
    unsigned track_bytes_written : 1;
    unsigned track_window : 1;
    unsigned adb_encoding_hack : 1;
    unsigned leftover_escape : 2;
};

struct channel* channel_new(struct fdh* fdh,
                            size_t rbsz,
                            enum channel_direction direction);

struct pollfd channel_request_poll(struct channel* c);
void channel_poll(struct channel* c);

void channel_write(struct channel* c,
                   const struct iovec* iov,
                   unsigned nio);

void channel_close(struct channel* c);

bool channel_dead_p(struct channel* c);
