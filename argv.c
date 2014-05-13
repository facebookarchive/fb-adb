#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include "argv.h"
#include "util.h"

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

const char**
argv_concat(const char* const* argv1, ...)
{
    va_list args;
    const char* const* argv;
    size_t totalnr = 0;
    va_start(args, argv1);
    argv = argv1;
    while (argv) {
        if (SATADD(&totalnr, totalnr, argv_count(argv)))
            die(EINVAL, "arglist too long");
        argv = va_arg(args, const char* const*);
    }
    va_end(args);

    const char** new_argv;

    if (totalnr == SIZE_MAX ||
        totalnr + 1 > SIZE_MAX / sizeof (*new_argv))
    {
        die(EINVAL, "arglist too long");
    }

    new_argv = xalloc(sizeof (*new_argv) * (1 + totalnr));
    unsigned pos = 0;
    va_start(args, argv1);
    argv = argv1;
    while (argv) {
        while (*argv) {
            new_argv[pos++] = *argv;
            ++argv;
        }
        argv = va_arg(args, const char* const*);
    }
    va_end(args);

    assert(pos == totalnr);
    new_argv[totalnr] = NULL;
    return new_argv;
}

const char* const empty_argv[] = { NULL };
