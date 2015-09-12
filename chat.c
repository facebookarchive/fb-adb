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
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include "util.h"
#include "chat.h"
#include "fs.h"

__attribute__((noreturn))
static void chat_die(void)
{
    die(ECOMM, "lost connection to child");
}


struct chat*
chat_new(int to, int from)
{
    struct chat* cc = xcalloc(sizeof (*cc));
    cc->to = xfdopen(to, "w");
    cc->from = xfdopen(from, "r");
    return cc;
}

char
chat_getc(struct chat* cc)
{
    int c;

    {
        c = getc(cc->from);
    }

    if (c == EOF)
        chat_die();

    return c;
}

void
chat_expect(struct chat* cc, char expected)
{
    int c = chat_getc(cc);
    if ((char)c != expected) {
        die(ECOMM,
            "[child] expected 0x%02x %c, found 0x%02x %c",
            expected,
            isprint(expected) ? expected : '.',
            (char) c,
            isprint(c) ? c : '.');
    }
}

void
chat_expect_maybe(struct chat* cc, char expected)
{
    char c = chat_getc(cc);
    if (c != expected)
        ungetc(c, cc->from);
}

void
chat_swallow_prompt(struct chat* cc)
{
    /* 100% reliable prompt detection */
    unsigned csi_arg = 0;
    enum { S_NORMAL, S_AFTER_ESC, S_AFTER_CSI } state = S_NORMAL;

    for (;;) {
        char c = chat_getc(cc);
        if (c == '#' || c == '$')
            break;

        // Some systems run resize(1), part of busybox, when an
        // interactive shell connects.  The state machine below looks
        // for status queries from this program and replies with a
        // fake answer.  Ignoring the query leads to busybox waiting
        // three seconds for an answer before giving up.

        // For details of the control codes, see
        // http://invisible-island.net/xterm/ctlseqs/ctlseqs.html

        switch (state) {
            default:
            case S_NORMAL:
                if (c == '\033')
                    state = S_AFTER_ESC;
                break;

            case S_AFTER_ESC:
                if (c == '[') {
                    state = S_AFTER_CSI;
                    csi_arg = 0;
                } else {
                    state = S_NORMAL;
                }

                break;

            case S_AFTER_CSI:
                if ('0' <= c && c <= '9') {
                    csi_arg = 10 * csi_arg + c-'0';
                } else if (c == 'n') {
                    if (csi_arg == 5) {
                        if (fputs("\033[0n", cc->to) == EOF)
                            chat_die();
                    } else if (csi_arg == 6) {
                        if (fputs("\033[25;80R", cc->to) == EOF)
                            chat_die();
                    }
                    if (fflush(cc->to) == EOF)
                        chat_die();

                    state = S_NORMAL;
                } else {
                    state = S_NORMAL;
                }

                break;
        }
    }

    chat_expect(cc, ' ');
}

void
chat_talk_at(struct chat* cc, const char* what)
{
    if (fputs(what, cc->to) == EOF)
        chat_die();

    if (putc('\n', cc->to) == EOF)
        chat_die();

    if (fflush(cc->to) == EOF)
        chat_die();

    /* We expect the child to echo us, so read back the echoed
     * characters.  */
    while (*what)
        chat_expect(cc, *what++);

    /* Yes, this is really what comes back after a \n.  */
    chat_expect(cc, '\r');
    chat_expect_maybe(cc, '\r');
    chat_expect(cc, '\n');
}

char*
chat_read_line(struct chat* cc)
{
    size_t linesz;
    char* line = slurp_line(cc->from, &linesz);
    if (line == NULL)
        die(ECOMM, "lost connection to child");
    rtrim(line, &linesz, "\r\n");
    return line;
}
