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
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
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

struct strlist_node {
    STAILQ_ENTRY(strlist_node) link;
    char string[];
};

struct strlist {
    STAILQ_HEAD(, strlist_node) head;
    struct strlist_node* cursor;
};

static void
strlist_cleanup(void* data)
{
    struct strlist* sl = data;
    while (!STAILQ_EMPTY(&sl->head)) {
        struct strlist_node* sln = STAILQ_FIRST(&sl->head);
        STAILQ_REMOVE_HEAD(&sl->head, link);
        free(sln);
    }
}

struct strlist*
strlist_new(void)
{
    struct cleanup* cl = cleanup_allocate();
    struct strlist* sl = xcalloc(sizeof (*sl));
    STAILQ_INIT(&sl->head);
    cleanup_commit(cl, strlist_cleanup, sl);
    return sl;
}

void
strlist_append(struct strlist* sl, const char* s)
{
    size_t s_len = strlen(s);
    size_t allocsz = offsetof(struct strlist_node, string);
    allocsz += s_len + 1;
    struct strlist_node* sln = malloc(allocsz);
    if (sln == NULL)
        die_oom();
    memset(sln, 0, sizeof (*sln));
    memcpy(&sln->string, s, s_len+1);
    STAILQ_INSERT_TAIL(&sl->head, sln, link);
}

void
strlist_extend(struct strlist* sl, const struct strlist* src)
{
    for (const char* s = strlist_rewind(src);
         s != NULL;
         s = strlist_next(src))
    {
        strlist_append(sl, s);
    }
}

void
strlist_extend_argv(struct strlist* sl, const char* const* src)
{
    while (*src)
        strlist_append(sl, *src++);
}

struct strlist*
strlist_from_argv(const char* const* argv)
{
    struct strlist* sl = strlist_new();
    strlist_extend_argv(sl, argv);
    return sl;
}

const char*
strlist_rewind(const struct strlist* sl)
{
    struct strlist* slm = (struct strlist*) sl;
    slm->cursor = STAILQ_FIRST(&slm->head);
    return slm->cursor ? slm->cursor->string : NULL;
}

const char*
strlist_next(const struct strlist* sl)
{
    struct strlist* slm = (struct strlist*) sl;
    if (slm->cursor)
        slm->cursor = STAILQ_NEXT(slm->cursor, link);
    return slm->cursor ? slm->cursor->string : NULL;
}

const char**
strlist_to_argv(const struct strlist* sl)
{
    size_t argc = 0;
    for (const char* s = strlist_rewind(sl);
         s != NULL;
         s = strlist_next(sl))
    {
        ++argc;
    }

    const char** argv = xalloc(sizeof (*argv)*(1+argc));
    const char** pos = argv;
    for (const char* s = strlist_rewind(sl);
         s != NULL;
         s = strlist_next(sl))
    {
        *pos++ = s;
    }
    *pos = NULL;
    return argv;
}

#ifndef STAILQ_CONCAT
#define	STAILQ_CONCAT(head1, head2) do {				\
        if (!STAILQ_EMPTY((head2))) {					\
                *(head1)->stqh_last = (head2)->stqh_first;		\
                (head1)->stqh_last = (head2)->stqh_last;		\
                STAILQ_INIT((head2));					\
        }								\
} while (/*CONSTCOND*/0)
#endif

void
strlist_xfer(struct strlist* recipient, struct strlist* donor)
{
    STAILQ_CONCAT(&recipient->head, &donor->head);
}

bool
strlist_empty_p(const struct strlist* sl)
{
    return STAILQ_EMPTY(&sl->head);
}
