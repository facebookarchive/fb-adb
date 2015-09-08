// Copyright (c) 2008-2010 Bjoern Hoehrmann <bjoern@hoehrmann.de>
// See http://bjoern.hoehrmann.de/utf-8/decoder/dfa/ for details.

#pragma once
#include <stdint.h>
#define UTF8_ACCEPT 0
#define UTF8_REJECT 12
uint32_t utf8_decode(uint32_t* state, uint32_t byte);
