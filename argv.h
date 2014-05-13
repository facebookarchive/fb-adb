#pragma once
#include <stddef.h>
size_t argv_count(const char* const* argv);

const char** argv_concat(const char* const* argv1, ...);
extern const char* const empty_argv[];
