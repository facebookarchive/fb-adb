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

// An fdrecorder, through dark magic unix and firelit sacrifices to
// SIGIO (the ancient and terrible God of level-triggered event
// handling), records all writes to its associate write fd from this
// program or, more importantly, _any_ _other_ _program_, even after
// we close our own copy of the fdrecorder's write fd.  We only stop
// recordng when all copies of the write FD and closed or when an
// fdrecorder it scraped off its parent reslist.

struct fdrecorder;

// Make a new fdrecorder; it begins recording immediately.
struct fdrecorder* fdrecorder_new(void);

// Retrieve the write end of the fdrecorder.  Writes to this FD or any
// duplicate of it from any program get sucked into the fdrecorder's
// internal buffer.
int fdrecorder_write_fd(struct fdrecorder* fdr);

// Close our copy of the write descriptor.  Other copies can live as
// long as you'd like.
void fdrecorder_close_write_fd(struct fdrecorder* fdr);

// Retrieve the currently-recorded bytes, ownership of which is
// transferred to the caller's reslist.  Empties the fdrecorder buffer
// by side effect.
struct growable_buffer fdrecorder_get_clean(struct fdrecorder* fdr);
