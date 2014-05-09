#pragma once

#ifdef __ANDROID__
#define DEFAULT_SHELL "/system/bin/sh"
#else
#define DEFAULT_SHELL "/bin/sh"
#endif

#define DEFAULT_CMD_BUFSZ 4096
#define DEFAULT_STREAM_BUFSZ 4096
