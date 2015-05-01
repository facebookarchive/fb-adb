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
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include "argv.h"
#include "util.h"

const char* const empty_argv[] = { NULL };

size_t
argv_count(const char* const* argv)
{
    size_t nr = 0;
    while (*argv) {
        ++nr;
        ++argv;
    }

    return nr;
}

static const char**
argv_concat_internal(bool deepcopy, const char* const* argv1, va_list args)
{
    const char* const* argv;
    size_t totalnr = 0;
    {
        va_list args2;
        va_copy(args2, args);
        argv = argv1;
        while (argv) {
            if (SATADD(&totalnr, totalnr, argv_count(argv)))
                die(EINVAL, "arglist too long");
            argv = va_arg(args2, const char* const*);
        }
        va_end(args2);
    }

    const char** new_argv;

    if (totalnr == SIZE_MAX ||
        totalnr + 1 > SIZE_MAX / sizeof (*new_argv))
    {
        die(EINVAL, "arglist too long");
    }

    new_argv = xalloc(sizeof (*new_argv) * (1 + totalnr));
    unsigned pos = 0;
    argv = argv1;
    while (argv) {
        while (*argv) {
            new_argv[pos++] = deepcopy ? xstrdup(*argv) : *argv;
            ++argv;
        }
        argv = va_arg(args, const char* const*);
    }

    assert(pos == totalnr);
    new_argv[totalnr] = NULL;
    return new_argv;
}

const char**
argv_concat_deepcopy(const char* const* argv1, ...)
{
    va_list args;
    va_start(args, argv1);
    const char** ret = argv_concat_internal(true, argv1, args);
    va_end(args);
    return ret;
}

const char**
argv_concat(const char* const* argv1, ...)
{
    va_list args;
    va_start(args, argv1);
    const char** ret = argv_concat_internal(false, argv1, args);
    va_end(args);
    return ret;
}
