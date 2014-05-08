#pragma once

#ifdef NDEBUG
#define dbg(...) (void)
#define dbglock() (void)
#else
__attribute__((format(printf, 1, 2)))
void dbg(const char* fmt, ...);
void dbg_init(void);
void dbglock(void);
void dbglock_init(void);
struct iovec;
struct ringbuf;
struct msg;
struct channel;
void iovec_dbg(const struct iovec* iov, unsigned nio);
void ringbuf_dbg(const struct ringbuf* rb);
const char* chname(int chno);
void dbgmsg(struct msg* msg, const char* tag);
void dbgch(const char* label, struct channel** ch, unsigned nrch);
#endif
