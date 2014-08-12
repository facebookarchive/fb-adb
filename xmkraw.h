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
struct termios;
void xtcgetattr(int fd, struct termios* attr);
void xtcsetattr(int fd, struct termios* attr);
#define XMKRAW_SKIP_CLEANUP 0x1
void xmkraw(int fd, unsigned flags);
