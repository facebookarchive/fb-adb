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
#include "androidmsg.h"
#include "util.h"
#include "dbg.h"

# define LOG_TAG PACKAGE

void
android_msg(int prio, const char* fmt, ...)
{
    va_list args;
    (void) args;
#ifdef __ANDROID__
    va_start(args, fmt);
    (void) __android_log_vprint(prio, LOG_TAG, fmt, args);
    va_end(args);
#endif
#ifndef NDEBUG
    if (dbg_enabled_p()) {
        va_start(args, fmt);
        dbg_1v(fmt, args);
        va_end(args);
    }
#endif
}
