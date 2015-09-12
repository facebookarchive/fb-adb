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
#include <stdbool.h>
#include "proto.h"

struct stub_daemon_info {
    unsigned daemonize : 1;
    unsigned replace : 1;
};

enum stub_daemon_action {
    STUB_DAEMON_EXIT_PROGRAM,
    STUB_DAEMON_RUN_STUB,
};

enum stub_daemon_action run_stub_daemon(struct stub_daemon_info info);
void start_daemon_via_service_hack(const char* package_name);
void stop_daemon(void);
