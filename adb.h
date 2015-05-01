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
void adb_send_file(const char* local,
                   const char* remote,
                   const char* const* adb_args);

void adb_rename_file(const char* old_name,
                     const char* new_name,
                     const char* const* adb_args);

void adb_delete_file(const char* name,
                     const char* const* adb_args);
