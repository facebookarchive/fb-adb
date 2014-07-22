// Copyright 2004-present Facebook. All Rights Reserved.
#include "strutil.h"

void
lim_outc(char c, size_t *pos, char *buf, size_t bufsz)
{
    if (*pos < bufsz) {
        buf[*pos] = c;
    }

    *pos += 1;
}

void
lim_strcat(const char* s, size_t *pos, char *buf, size_t bufsz)
{
    char c;

    while ((c = *s++)) {
        lim_outc(c, pos, buf, bufsz);
    }
}

void
lim_shellquote(const char* word, size_t *pos, char *buf, size_t bufsz)
{
    char c;

    lim_strcat("'", pos, buf, bufsz);
    while ((c = *word++)) {
        if (c == '\'') {
            lim_strcat("'\\''", pos, buf, bufsz);
        } else {
            lim_outc(c, pos, buf, bufsz);
        }
    }

    lim_strcat("'", pos, buf, bufsz);
}
