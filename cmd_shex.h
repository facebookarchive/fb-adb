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
#include <getopt.h>

int shex_main(int argc, const char** argv);
int shex_main_rcmd(int argc, const char** argv);

int shex_wrapper(const char* wrapped_cmd,
                 const char* opts,
                 const struct option* longopts,
                 const char* usage,
                 const char** argv);
