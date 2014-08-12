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
#include <termios.h>
#include <unistd.h>
#include "termbits.h"
#include "util.h"

const struct termbit termbits[] = {
#define IFLAG(x) { TERM_IFLAG, x, #x },
#define OFLAG(x) { TERM_OFLAG, x, #x },
#define LFLAG(x) { TERM_LFLAG, x, #x },
#define C_CC(x)  { TERM_C_CC, x, #x },
#include "termnames.h"
};

const unsigned nr_termbits = ARRAYSIZE(termbits);
