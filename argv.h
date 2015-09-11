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
#pragma once
#include <stddef.h>

size_t argv_count(const char* const* argv);

const char** argv_concat(const char* const* argv1, ...);
const char** argv_concat_deepcopy(const char* const* argv1, ...);
extern const char* const empty_argv[];

#define ARGV(...) ((const char*[]){__VA_ARGS__ , NULL})
#define ARGV_CONCAT(...) argv_concat(__VA_ARGS__ , NULL)

struct strlist;
__attribute__((malloc))
struct strlist* strlist_new(void);
void strlist_append(struct strlist* sl, const char* s);
void strlist_extend(struct strlist* sl, const struct strlist* src);
void strlist_extend_argv(struct strlist* sl, const char* const* src);
struct strlist* strlist_from_argv(const char* const* argv);
const char* strlist_rewind(const struct strlist* sl);
const char* strlist_next(const struct strlist* sl);
const char** strlist_to_argv(const struct strlist* sl);
void strlist_xfer(struct strlist* recipient, struct strlist* donor);
bool strlist_empty_p(const struct strlist* sl);
