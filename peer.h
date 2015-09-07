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

#include "autocmd.h"
#include "child.h"

struct start_peer_info {
    const struct cwd_opts cwd;
    const struct adb_opts adb;
    const struct transport_opts transport;
    const struct user_opts user;
};

struct child* start_peer(
    const struct start_peer_info* spi,
    const char* stub_command,
    struct strlist* stub_arguments);
