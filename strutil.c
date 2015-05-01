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
#include <string.h>
#include "strutil.h"
#include "util.h"

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
    if (shell_safe_word_p(word)) {
        lim_strcat(word, pos, buf, bufsz);
    } else {
        char c;
        lim_strcat("'", pos, buf, bufsz);
        while ((c = *word++)) {
            if (c < ' ' || c == (char) 0x7F)
                die(EINVAL, "control characters in shell word");
            if (c == '\'') {
                lim_strcat("'\\''", pos, buf, bufsz);
            } else {
                lim_outc(c, pos, buf, bufsz);
            }
        }

        lim_strcat("'", pos, buf, bufsz);
    }
}

bool
shell_safe_word_p(const char* word)
{
    if (*word == '\0')
        return false; // Empty words must be quoted

    while (*word) {
        char c = *word++;
        if (('a' <= c && c <= 'z') ||
            ('A' <= c && c <= 'Z') ||
            ('0' <= c && c <= '9') ||
            strchr("-_/.", c))
        {
            /* Safe */
        } else {
            return false;
        }
    }

    return true;
}

char*
xshellquote(const char* word)
{
    size_t bufsz = 0;
    lim_shellquote(word, &bufsz, NULL, 0);
    char* quoted = xalloc(bufsz+1);
    size_t pos = 0;
    lim_shellquote(word, &pos, quoted, bufsz);
    quoted[bufsz] = '\0';
    return quoted;
}
