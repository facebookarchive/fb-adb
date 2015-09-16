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
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include "util.h"
#include "autocmd.h"
#include "fs.h"
#include "json.h"

#if FBADB_MAIN

FORWARD(getprop);

#elif !defined(__ANDROID__)

int
getprop_main(const struct cmd_getprop_info* info)
{
    die(ENOSYS, "Android properties not supported on this system");
}

#else

#include <sys/system_properties.h>
#include <dlfcn.h>

// N.B. The Android property system uses prop_info* as an
// interned key for a property name.  A given prop_info pointer is
// valid for the lifetime of the system, so we don't have to worry
// about properties disappearing from under us.  We use
// system_property_foreach when it's available, as the _nth variant
// become inefficient when Android 4.4 switched to a
// trie implementation.

static int (*property_foreach)(
        void (*propfn)(const prop_info *pi, void *cookie),
        void *cookie);

struct property_vector {
    size_t size;
    size_t capacity;
    const prop_info** props;
};

struct find_all_properties_context {
    struct property_vector* pv;
    bool oom;
};

static void
property_vector_cleanup(void* data)
{
    struct property_vector* pv = data;
    free(pv->props);
}

static struct property_vector*
property_vector_new(void)
{
    struct cleanup* cl = cleanup_allocate();
    struct property_vector* pv = xalloc(sizeof (*pv));
    pv->capacity = 16;
    pv->size = 0;
    pv->props = malloc(sizeof (pv->props[0]) * pv->capacity);
    cleanup_commit(cl, property_vector_cleanup, pv);
    return pv;
}

static bool
property_vector_append(struct property_vector* pv, const prop_info* pi)
{
    if (pv->size == pv->capacity) {
        size_t new_capacity;
        if (SATADD(&new_capacity, pv->capacity, pv->capacity))
            return false;

        if (new_capacity > SIZE_MAX / sizeof (const prop_info*))
            return false;

        size_t allocsz = new_capacity * sizeof (const prop_info*);

        const prop_info** new_props = resize_alloc(pv->props, allocsz);
        if (new_props == NULL)
            return false;

        pv->props = new_props;
        pv->capacity = new_capacity;
    }

    pv->props[pv->size++] = pi;
    return true;
}

static void
find_all_properties_propfn(const prop_info* pi, void* cookie)
{
    struct find_all_properties_context* ctx = cookie;
    if (!ctx->oom)
        if (!property_vector_append(ctx->pv, pi))
            ctx->oom = true;
}

static int
property_compare(const void* a, const void* b)
{
    const prop_info* pa;
    const prop_info* pb;
    memcpy(&pa, a, sizeof (pa));
    memcpy(&pb, b, sizeof (pb));
    char name_a[PROP_NAME_MAX];
    char name_b[PROP_NAME_MAX];
    char value[PROP_VALUE_MAX];
    (void) __system_property_read(pa, name_a, value);
    (void) __system_property_read(pb, name_b, value);
    return strcmp(name_a, name_b);
}

static void
property_vector_sort(struct property_vector* pv)
{
    qsort(pv->props, pv->size, sizeof (pv->props[0]), property_compare);
}

static struct property_vector*
find_all_properties_raw(void)
{
    for (;;) {
        SCOPED_RESLIST(rl);

        struct find_all_properties_context ctx = {
            .pv = property_vector_new(),
            .oom = false,
        };

        if (property_foreach(find_all_properties_propfn, &ctx) == 1)
            continue;

        if (ctx.oom)
            die_oom();
        reslist_xfer(rl->parent, rl);
        property_vector_sort(ctx.pv);
        return ctx.pv;
    }
}

static void
property_vector_swap(struct property_vector* a,
                     struct property_vector* b)
{
    struct property_vector tmp = *a;
    *a = *b;
    *b = tmp;
}

static bool
property_vector_equal(const struct property_vector* a,
                      const struct property_vector* b)
{
    return a->size == b->size &&
        memcmp(a->props, b->props, a->size * sizeof (a->props[0])) == 0;
}

static struct property_vector*
find_all_properties(void)
{
    struct property_vector* pv1 = find_all_properties_raw();
    for (;;) {
        SCOPED_RESLIST(pv);
        struct property_vector* pv2 = find_all_properties_raw();
        if (property_vector_equal(pv1, pv2))
            return pv1;
        property_vector_swap(pv1, pv2);
    }
}

static int
compat_property_foreach(
    void (*propfn)(const prop_info *pi, void *cookie),
    void *cookie)
{
    unsigned propno = 0;
    for (;;) {
        const prop_info* pi = __system_property_find_nth(propno++);
        if (pi == NULL)
            break;
        propfn(pi, cookie);
    }
    return 0;
}

static int
property_argv_compare(const void* a, const void* b)
{
    const char* sa;
    const char* sb;
    memcpy(&sa, a, sizeof (sa));
    memcpy(&sb, b, sizeof (sb));
    return strcmp(sa, sb);
}

static void
output_property(bool* first,
                char sep,
                const char* format,
                const char* name,
                const char* value)
{
    if (*first)
        *first = false;
    else
        xputc(sep, xstdout);

    char c;
    bool escaped = false;
    while ((c = *format++)) {
        if (escaped) {
            if (c == '%') {
                xputc('%', xstdout);
            } else if (c == 'n') {
                xputs(name, xstdout);
            } else if (c == 'v' && value) {
                xputs(value, xstdout);
            } else {
                usage_error("incorrect format string \"%s\"", format-2);
            }
            escaped = false;
        } else {
            if (c == '%') {
                escaped = true;
            } else {
                xputc(c, xstdout);
            }
        }
    }
}

int
getprop_main(const struct cmd_getprop_info* info)
{
    const char* format = info->getprop.format;
    const char* format_not_found = info->getprop.format_not_found;
    bool null = info->getprop.null;
    if (null && format == NULL && format_not_found == NULL)
        usage_error("must supply --format or "
                    "--format-not-found or both if using -0");

    if (property_foreach == NULL) {
        void* libc = dlopen("libc.so", RTLD_LAZY);
        if (libc != NULL)
            property_foreach = dlsym(libc, "__system_property_foreach");
    }

    if (property_foreach == NULL)
        property_foreach = compat_property_foreach;

    dbg("using %s for property enumeration",
        property_foreach == compat_property_foreach
        ? "compat_property_foreach"
        : "__system_property_foreach");

    int exit_status = 0;

    struct json_writer* writer = NULL;
    if (format == NULL && format_not_found == NULL) {
        writer = json_writer_create(xstdout);
        json_begin_object(writer);
    }

    const char** properties = ARGV_CONCAT(info->properties);
    bool first = true;
    char sep = null ? '\0' : '\n';
    if (*properties == NULL) {
        struct property_vector* pv = find_all_properties();
        char prev_name[PROP_NAME_MAX];
        for (size_t i = 0; i < pv->size; ++i) {
            char name[PROP_NAME_MAX];
            char value[PROP_VALUE_MAX];
            (void) __system_property_read(pv->props[i], name, value);
            if (i > 0 && strcmp(name, prev_name) == 0)
                continue;
            if (writer != NULL) {
                json_begin_field(writer, name);
                json_emit_string(writer, value);
            } else {
                output_property(&first, sep, format, name, value);
            }
            strcpy(prev_name, name);
        }
    } else {
        size_t nproperties = argv_count(properties);
        qsort(properties,
              nproperties,
              sizeof (properties[0]),
              property_argv_compare);
        const char* property;
        const char* prev_property = NULL;
        while ((property = *properties++)) {
            if (prev_property != NULL && !strcmp(prev_property, property))
                continue;
            if (writer != NULL)
                json_begin_field(writer, property);
            const prop_info* pi = __system_property_find(property);
            if (pi) {
                char value[PROP_VALUE_MAX];
                __system_property_read(pi, NULL, value);
                if (writer != NULL)
                    json_emit_string(writer, value);
                else if (format != NULL)
                    output_property(&first, sep, format, property, value);
            } else {
                if (writer != NULL)
                    json_emit_null(writer);
                else if (format_not_found != NULL)
                    output_property(&first, sep,
                                    format_not_found,
                                    property, NULL);
                exit_status = 4;
            }
            prev_property = property;
        }
    }

    if (writer == NULL && !first && !null)
        xputc(sep, xstdout);

    if (writer != NULL)
        json_end_object(writer);

    xflush(xstdout);
    return exit_status;
}

#endif
