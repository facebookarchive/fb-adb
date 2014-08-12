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

struct termbit {
    enum { TERM_IFLAG, TERM_OFLAG, TERM_LFLAG, TERM_C_CC } thing;
    unsigned long value;
    const char* name;
};

extern const struct termbit termbits[];
extern const unsigned nr_termbits;
