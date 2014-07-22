// Copyright 2004-present Facebook. All Rights Reserved.
#pragma once

#ifdef __ANDROID__
#define DEFAULT_SHELL "/system/bin/sh"
#define DEFAULT_TEMP_DIR "/data/local/tmp"
#else
#define DEFAULT_SHELL "/bin/sh"
#define DEFAULT_TEMP_DIR "/tmp"
#endif

#define DEFAULT_CMD_BUFSZ 4096
#define DEFAULT_STREAM_BUFSZ 4096
#define FB_ADB_REMOTE_FILENAME "/data/local/tmp/fb-adb"
