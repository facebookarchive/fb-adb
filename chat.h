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

#include <stdio.h>
#include <stdbool.h>

struct chat {
    FILE* to;
    FILE* from;
};

struct chat* chat_new(int to, int from);
char chat_getc(struct chat* cc);
void chat_expect(struct chat* cc, char expected);
void chat_swallow_prompt(struct chat* cc);
void chat_talk_at(struct chat* cc, const char* what);
char* chat_read_line(struct chat* cc);
