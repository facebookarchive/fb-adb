// Copyright 2004-present Facebook. All Rights Reserved.
#pragma once
void lim_outc(char c, size_t *pos, char *buf, size_t bufsz);
void lim_strcat(const char* s, size_t *pos, char *buf, size_t bufsz);
void lim_shellquote(const char* word, size_t *pos, char *buf, size_t bufsz);
