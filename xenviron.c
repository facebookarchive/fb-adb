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
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "xenviron.h"

extern char** environ;

struct xenviron {
    char** env;
};

static size_t
xenviron_allocsz(size_t nr_slots)
{
    return (nr_slots + 1) * sizeof (char*);
}

static void
xenviron_cleanup(void* data)
{
    struct xenviron* xe = data;
    if (xe->env != NULL) {
        for (char** env = xe->env; *env; ++env)
            free(*env);
        free(xe->env);
    }

    free(xe);
}

struct xenviron*
xenviron_create(const char* const* copy_from)
{
    struct cleanup* cl = cleanup_allocate();
    struct xenviron* xe = calloc(1, sizeof (char*));
    if (xe == NULL)
        die_oom();
    cleanup_commit(cl, xenviron_cleanup, xe);

    if (copy_from == NULL) {
        xe->env = calloc(1, xenviron_allocsz(0));
        if (xe->env == NULL)
            die_oom();
    } else {
        size_t nr = 0;
        for (const char* const* pos = copy_from; *pos; ++pos)
            nr += 1;

        xe->env = calloc(1, xenviron_allocsz(nr));
        if (xe->env == NULL)
            die_oom();

        for (size_t i = 0; i < nr; ++i) {
            xe->env[i] = strdup(copy_from[i]);
            if (xe->env[i] == NULL)
                die_oom();
        }
    }

    return xe;
}

struct xenviron*
xenviron_copy_environ(void)
{
    return xenviron_create((const char* const*) environ);
}

const char* const*
xenviron_as_environ(struct xenviron* xe)
{
    return (const char* const*) xe->env;
}

static const char*
xenviron_match(char* entry, const char* name)
{
    char* name_end = strchr(entry, '=');
    if (strncmp(name, entry, name_end - entry) == 0)
        return name_end + 1;
    return NULL;
}

const char*
xenviron_get(struct xenviron* xe, const char* name)
{
    const char* match;
    for (char** slot = xe->env; *slot; ++slot)
        if ((match = xenviron_match(*slot, name)) != NULL)
            return match;
    return NULL;
}

static char*
xenviron_allocate_entry(const char* name, const char* value)
{
    size_t name_length = strlen(name);
    size_t value_length = strlen(value);
    // If name and value do not alias, this value cannot overflow.
    size_t entry_alloc = name_length + 1 + value_length + 1;
    char* entry = malloc(entry_alloc);
    if (entry == NULL)
        die_oom();

    memcpy(&entry[0], name, name_length);
    entry[name_length] = '=';
    memcpy(&entry[name_length+1], value, value_length);
    entry[name_length + 1 + value_length] = '\0';
    return entry;
}

void
xenviron_set(struct xenviron* xe,
             const char* name,
             const char* value)
{
    char* new_entry = xenviron_allocate_entry(name, value);
    char** slot;

    for (slot = xe->env;  *slot; ++slot)
        if (xenviron_match(*slot, name) != NULL)
            break;

    if (*slot != NULL) {
        free(*slot);
        *slot = new_entry;
    } else {
        size_t nr_slots = (slot - xe->env) + 1;
        char** new_env = realloc(xe->env, xenviron_allocsz(nr_slots));
        if (new_env == NULL) {
            free(new_entry);
            die_oom();
        }

        xe->env = new_env;
        new_env[nr_slots] = NULL;
        new_env[nr_slots - 1] = new_entry;
    }
}

void
xenviron_unset(struct xenviron* xe, const char* name)
{
    char** env = xe->env;
    char** slot;

    for (slot = xe->env;  *slot; ++slot)
        if (xenviron_match(*slot, name) != NULL)
            break;

    if (*slot != NULL) {
        char** slot_end = slot;
        while (*slot_end)
            ++slot_end;

        size_t nr_slots = slot_end - env;
        size_t nr_to_move = slot_end - slot;

        free(slot[0]);
        memmove(&slot[0], &slot[1], xenviron_allocsz(nr_to_move));
        char** new_env = realloc(env, xenviron_allocsz(nr_slots - 1));
        if (new_env != NULL)
            xe->env = new_env;
    }
}

void
xenviron_clear(struct xenviron* xe)
{
    for (char** slot = xe->env; *slot; ++slot) {
        free(*slot);
        *slot = NULL;
    }

    char** new_env = realloc(xe->env, xenviron_allocsz(0));
    if (new_env != NULL)
        xe->env = new_env;
}
