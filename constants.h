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

#define DEVICE_TEMP_DIR "/data/local/tmp"

#ifdef __ANDROID__
#define DEFAULT_SHELL "/system/bin/sh"
#define DEFAULT_TEMP_DIR DEVICE_TEMP_DIR
#else
#define DEFAULT_SHELL "/bin/sh"
#define DEFAULT_TEMP_DIR "/tmp"
#endif

#define FB_ADB_REMOTE_FILENAME DEVICE_TEMP_DIR "/fb-adb"

#define DEFAULT_STREAM_RINGBUFSZ (100*1024)

#define DEFAULT_MAX_CMDSZ 4096
#define DEFAULT_MAX_CMDSZ_SOCKET MSG_MAX_SIZE
