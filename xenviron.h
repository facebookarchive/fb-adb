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

struct xenviron;

struct xenviron* xenviron_create(const char* const* copy_from);
struct xenviron* xenviron_copy_environ(void);
const char* const* xenviron_as_environ(struct xenviron* xe);
const char* xenviron_get(struct xenviron* xe, const char* name);
void xenviron_set(struct xenviron* xe,
                  const char* name,
                  const char* value);
void xenviron_unset(struct xenviron* xe, const char* name);
void xenviron_clear(struct xenviron* xe);
