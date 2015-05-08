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
#include <errno.h>
#include <stddef.h>
#include "adbenc.h"
#include "util.h"

/* The sequences [\n ~ .] and [\r ~ .] typed into an adb pty act as an
 * emergency escape sequences and cause immediate disconnection.  Make
 * sure we never send these bytes.  The easiest way to do that is to
 * make sure we never send `~', a.k.a. adb_forbidden: adb_escape1
 * followed by adb_escape1 is adb_escape1, and adb_escape1 followed by
 * anything else is adb_forbidden.  */
static const char adb_forbidden = '~';
static const char adb_escape1 = '!';
static const char adb_escape2 = '@';

void
adb_encode(unsigned* inout_state,
           char** inout_enc,
           char* encend,
           const char** inout_in,
           const char* inend)
{
    unsigned state = *inout_state;
    char* enc = *inout_enc;
    const char* in = *inout_in;

    while (in < inend && enc < encend) {
        if (state == 0) {
             if (*in == adb_escape1) {
                *enc++ = adb_escape1;
                state = 1;
            } else if (*in == adb_forbidden) {
                *enc++ = adb_escape1;
                state = 2;
            } else {
                *enc++ = *in++;
            }
        } else if (state == 1) {
            *enc++ = adb_escape1;
            in++;
            state = 0;
        } else if (state == 2) {
            *enc++ = adb_escape2;
            in++;
            state = 0;
        }
    }

    *inout_state = state;
    *inout_enc = enc;
    *inout_in = in;
}

void
adb_decode(unsigned* inout_state,
           char** inout_dec,
           char* decend,
           const char** inout_in,
           const char* inend)
{
    unsigned state = *inout_state;
    char* dec = *inout_dec;
    const char* in = *inout_in;

    while (in < inend && dec < decend) {
        char c = *in++;
        if (state == 0) {
            if (c == adb_escape1)
                state = 1;
            else
                *dec++ = c;
        } else if (state == 1) {
            if (c == adb_escape1)
                *dec++ = adb_escape1;
            else
                *dec++ = adb_forbidden;

            state = 0;
        }
    }

    *inout_state = state;
    *inout_dec = dec;
    *inout_in = in;
}

size_t
read_all_adb_encoded(int fd, void* buf, size_t sz)
{
    char encbuf[4096];
    unsigned state = 0;
    char* dec = buf;
    char* decend = dec + sz;
    ssize_t ret;
    size_t nr_read = 0;

    while (nr_read < sz) {
        do {
            WITH_IO_SIGNALS_ALLOWED();
            ret = read(fd, encbuf, XMIN(sz - nr_read, sizeof (encbuf)));
        } while (ret == -1 && errno == EINTR);

        if (ret < 0)
            die_errno("read[adbenc]");

        if (ret < 1)
            break;

        const char* in = encbuf;
        const char* inend = encbuf + ret;
        char* cur_dec = dec;
        adb_decode(&state, &dec, decend, &in, inend);
        nr_read += dec - cur_dec;
    }

    return nr_read;
}

void
write_all_adb_encoded(int fd, const void* buf, size_t sz)
{
    char encbuf[4096];
    unsigned state = 0;
    const char* in = buf;
    const char* inend = in + sz;
    size_t nr_written = 0;

    while (nr_written < sz) {
        char* enc = encbuf;
        char* encend = enc + sizeof (encbuf);
        adb_encode(&state, &enc, encend, &in, inend);
        write_all(fd, encbuf, enc - encbuf);
        nr_written += enc - encbuf;
    }
}
