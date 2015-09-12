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

#define DEFAULT_MAX_CMDSZ 4096
#define DEFAULT_MAX_CMDSZ_SOCKET MSG_MAX_SIZE

// The LZ4 format is designed to work with 64k blocks, so there's no
// point letting it compress more.
#define MAX_COMPRESSION_BLOCK 65536

// LZ4 will emit all literals for blocks smaller than this value, so
// don't bother attempting to compressing them.
#define MIN_COMPRESSION_BLOCK 13

// This number of bytes of entropy protects against file and socket
// name collisions and makes the names of these things unguessable.
#define ENOUGH_ENTROPY 16

// Number of milliseconds the stub daemon will wait for a new
// connection before exiting
#define DAEMON_TIMEOUT_MS (5*60*1000)

// Number of milliseconds we wait for a TCP connection callback when
// we don't have an ADB stub process to monitor.
#define TCP_CALLBACK_MS (1*1000)

#define DAEMON_CONTROL_SUFFIX ".c"
