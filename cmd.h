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
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include "argv.h"
#define CMD_ARG_FORWARDED (1<<0)
#define CMD_ARG_NON_FORWARDED (1<<1)

typedef int (*cmdfn)(int argc, const char** argv);
struct cmd {
    const char* name;
    cmdfn main;
};

__attribute__((noreturn,format(printf,1,2)))
void usage_error(const char* fmt, ...);
__attribute__((noreturn))
void default_getopt(char c, const char* const* argv, const char* usage);
void append_argv_accumulation(struct strlist* sl,
                              const struct strlist* accum);
void accumulate_option(struct strlist** slp,
                       const char* opt,
                       const char* val);
struct cmd_rcmd_info;
int rcmd_main(const struct cmd_rcmd_info*);
int forward_to_rcmd(struct strlist* non_forwarded_args,
                    struct strlist* forwarded_args);

#ifdef FBADB_MAIN
# define FORWARD(cmd)                                                   \
    int cmd##_main(const struct cmd_##cmd##_info* info) {               \
    return forward_to_rcmd(                                             \
        make_args_cmd_##cmd(CMD_ARG_NON_FORWARDED, info),               \
        make_args_cmd_##cmd(CMD_ARG_FORWARDED, info));                  \
    }
#else
# define FORWARD(cmd)
#endif

void show_help(const char* help);

extern const char full_usage[];
