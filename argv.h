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
