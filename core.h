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
#include <stdbool.h>
#include <signal.h>
#include "util.h"
#include "proto.h"

struct channel;

enum channel_names {
    FROM_PEER,
    TO_PEER,
    NR_SPECIAL_CH = TO_PEER
};

struct fb_adb_sh {
    sigset_t* poll_sigmask;
    size_t max_outgoing_msg;
    unsigned nrch;
    unsigned turn; // Round-robin fairness state
    struct channel** ch;
    void (*process_msg)(struct fb_adb_sh* sh, struct msg mhdr);
};

void queue_message_synch(struct fb_adb_sh* sh, struct msg* m);
void io_loop_init(struct fb_adb_sh* sh);
void io_loop_pump(struct fb_adb_sh* sh);
void io_loop_do_io(struct fb_adb_sh* sh);
void fb_adb_sh_process_msg(struct fb_adb_sh* sh, struct msg mhdr);

void read_cmdmsg(struct fb_adb_sh* sh,
                 struct msg mhdr,
                 void* mbuf,
                 size_t msz);

#define PUMP_WHILE(_sh, _c)                     \
    ({                                          \
        struct fb_adb_sh* _m = (_sh);           \
        io_loop_pump(_m);                       \
        while ((_c)) {                          \
            io_loop_do_io(_m);                  \
            io_loop_pump(_m);                   \
        }                                       \
    })

typedef size_t (*reader)(int, void*,size_t);

__attribute__((malloc))
struct msg* read_msg(int fd, reader rdr);

void* check_msg_cast(struct msg* h, size_t minimum_size);
#define CHECK_MSG_CAST(_mhdr, _type) \
    ((_type *) check_msg_cast((_mhdr), sizeof (_type)))


struct daemon_hello {
    char ver[FB_ADB_FINGERPRINT_LENGTH+1];
    char socket_name[FB_ADB_STUB_DAEMON_SOCKET_NAME_LENGTH+1];
    unsigned pid;
};

bool parse_daemon_hello(const char* line, struct daemon_hello* dhello);
