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
#include "util.h"

struct termios;
struct ttysave;

void xtcgetattr(int fd, struct termios* attr);
void xtcsetattr(int fd, const struct termios* attr);

#define RAW_INPUT (1<<0)
#define RAW_OUTPUT (1<<1)

struct ttysave* ttysave_make_raw(int fd, unsigned flags);
void ttysave_restore(struct ttysave* tty, int fd, unsigned flags);
void ttysave_before_suspend(struct ttysave* tty, int fd);
void ttysave_after_resume(struct ttysave* tty, int fd);
void ttysave_after_sigcont(struct ttysave* tty, int fd);
