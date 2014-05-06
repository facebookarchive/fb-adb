#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "util.h"
#include "proto.h"

struct channel;

enum channel_names {
    FROM_PEER,
    TO_PEER,
    NR_SPECIAL_CH = TO_PEER
};

struct adbx_sh {
    size_t max_outgoing_msg;
    unsigned nrch;
    struct channel** ch;
    void (*process_msg)(struct adbx_sh* sh, struct msg mhdr);
};

void queue_message_synch(struct adbx_sh* sh, struct msg* m);
void io_loop_1(struct adbx_sh* sh);
void adbx_sh_process_msg(struct adbx_sh* sh, struct msg mhdr);
