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
#include "util.h"

void adb_send_file(const char* local,
                   const char* remote,
                   const char* const* adb_args);

// On at least one device, the LGLS770, rename somehow fails.
// On these devices, implement rename as cat and delete.  Yes, that's
// racy, but these devices deserve to lose.  What was the author of
// this SELinux policy thinking?!
#define ADB_RENAME_FALL_BACK_TO_CAT (1<<0)

void adb_rename_file(const char* old_name,
                     const char* new_name,
                     unsigned api_level,
                     unsigned rename_flags,
                     const char* const* adb_args);

void adb_add_forward(const char* local,
                     const char* remote,
                     const char* const* adb_args);

void adb_remove_forward(const char* local,
                        const char* const* adb_args);

struct remove_forward_cleanup;

struct remove_forward_cleanup* remove_forward_cleanup_allocate(
    const char* local,
    const char* const* adb_args);

void remove_forward_cleanup_commit(struct remove_forward_cleanup* rfc);

char* adb_getprop(const char* property, const char* const* adb_args);
unsigned adb_api_level(const char* const* adb_args);
