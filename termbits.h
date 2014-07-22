// Copyright 2004-present Facebook. All Rights Reserved.
#pragma once

struct termbit {
    enum { TERM_IFLAG, TERM_OFLAG, TERM_LFLAG, TERM_C_CC } thing;
    unsigned long value;
    const char* name;
};

extern const struct termbit termbits[];
extern const unsigned nr_termbits;
