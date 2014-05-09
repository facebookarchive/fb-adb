#pragma once

struct termbit {
    enum { TERM_IFLAG, TERM_OFLAG, TERM_LFLAG, TERM_C_CC } thing;
    unsigned long value;
    const char* name;
};

extern struct termbit termbits[];
extern unsigned nr_termbits;
