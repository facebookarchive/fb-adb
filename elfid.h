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
#include <stdint.h>
#include <stdbool.h>
#include "proto.h"

bool elf_compatible_p(int fd,
                      unsigned api_level,
                      unsigned abi_mask);
