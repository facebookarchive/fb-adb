// Copyright 2004-present Facebook. All Rights Reserved.
#pragma once
#include <stdio.h>

#ifdef NDEBUG
#define dbg(...) ({;})
#define dbglock() ({;})
#define dbg_init() ({;})
#define dbglock_init() ({;})
#define dbgmsg(...) ({;})
#define dbgch(...) ({;})
#else
struct iovec;
struct ringbuf;
struct msg;
struct channel;
extern FILE* dbgout;
#define dbg(...) ({ if (dbgout) dbg_1(__VA_ARGS__); })
__attribute__((format(printf, 1, 2)))
void dbg_1(const char* fmt, ...);
void dbg_init(void);
void dbglock(void);
void dbglock_init(void);
void iovec_dbg(const struct iovec* iov, unsigned nio);
void ringbuf_dbg(const struct ringbuf* rb);
const char* chname(int chno);
void dbgmsg(struct msg* msg, const char* tag);
void dbgch(const char* label, struct channel** ch, unsigned nrch);
#endif
