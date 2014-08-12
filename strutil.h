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
void lim_outc(char c, size_t *pos, char *buf, size_t bufsz);
void lim_strcat(const char* s, size_t *pos, char *buf, size_t bufsz);
void lim_shellquote(const char* word, size_t *pos, char *buf, size_t bufsz);
