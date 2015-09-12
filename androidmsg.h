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

#ifdef __ANDROID__
# include <android/log.h>
#endif

#ifndef __ANDROID__
# define ANDROID_LOG_DEBUG 0
# define ANDROID_LOG_INFO 0
# define ANDROID_LOG_WARN 0
# define ANDROID_LOG_ERROR 0
#endif

__attribute__((format(printf, 2, 3)))
void android_msg(int prio, const char* fmt, ...);
