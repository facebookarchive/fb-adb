// Copyright 2004-present Facebook. All Rights Reserved.
#pragma once
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <poll.h>
#include <sys/queue.h>
#include "dbg.h"

#ifndef ECOMM
#define ECOMM EBADRPC
#endif

#define ARRAYSIZE(ar) (sizeof (ar) / sizeof (*(ar)))

typedef void (*cleanupfn)(void* data);

struct resource {
    enum { RES_RESLIST, RES_RESLIST_ONSTACK, RES_CLEANUP } type;
    LIST_ENTRY(resource) link;
};

struct reslist {
    struct resource r;
    struct reslist* parent;
    LIST_HEAD(,resource) contents;
};

struct cleanup {
    struct resource r;
    cleanupfn fn;
    void* fndata;
};

struct reslist* reslist_push_new(void);
void reslist_init_local(struct reslist* rl_local);
void reslist_cleanup_local(struct reslist* rl_local);
void reslist_pop_nodestroy(struct reslist* rl);
void reslist_destroy(struct reslist* rl);
struct reslist* reslist_current(void);

#define PASTE(a,b) a##b

#define SCOPED_RESLIST(varname)                         \
    __attribute__((cleanup(reslist_cleanup_local)))     \
    struct reslist PASTE(varname,__);                   \
    struct reslist* varname = &PASTE(varname,__);       \
    reslist_init_local(varname);

struct cleanup* cleanup_allocate(void);
void cleanup_commit(struct cleanup* cl, cleanupfn fn, void* fndata);
void cleanup_commit_close_fd(struct cleanup* cl, int fd);

__attribute__((malloc))
void* xalloc(size_t sz);
__attribute__((malloc))
void* xcalloc(size_t sz);

int xopen(const char* pathname, int flags, mode_t mode);
void xpipe(int* read_end, int* write_end);
int xdup(int fd);
FILE* xfdopen(int fd, const char* mode);

struct fdh {
    struct reslist* rl; // Owns both fd and fdh
    int fd;
};

struct fdh* fdh_dup(int fd);
void fdh_destroy(struct fdh* fdh);

__attribute__((malloc,format(printf, 1, 2)))
char* xaprintf(const char* fmt, ...);
__attribute__((malloc))
char* xavprintf(const char* fmt, va_list args);
__attribute__((malloc))
char* xstrdup(const char* s);

typedef struct errinfo {
    int err;
    const char* msg;
    const char* prgname;
    unsigned want_msg : 1;
} errinfo;

bool catch_error(void (*fn)(void* fndata),
                 void* fndata,
                 struct errinfo* ei);

__attribute__((noreturn))
void diev(int err, const char* fmt, va_list args);
__attribute__((noreturn,format(printf, 2, 3)))
void die(int err, const char* fmt, ...);
__attribute__((noreturn,format(printf, 1, 2)))
void die_errno(const char* fmt, ...);

extern const char* orig_argv0;
extern const char* prgname;
void set_prgname(const char* s);
extern int real_main(int argc, char** argv);

size_t nextpow2sz(size_t sz);

#define XMIN(a,b)                \
    ({ typeof (a) _a = (a);      \
        typeof (a) _b = (b);     \
        _a > _b ? _b : _a; })

#define XMAX(a,b)                \
    ({ typeof (a) _a = (a);      \
        typeof (a) _b = (b);     \
        _a > _b ? _a : _b; })

#define SATADD(r, a, b)                         \
    ({                                          \
        typedef __typeof((*(r))) xT;            \
        xT xa = (a);                            \
        xT xb = (b);                            \
        int overflow;                           \
        if (((xT) -1) - xa < xb) {              \
            overflow = 1;                       \
            *(r) = ((xT) -1);                   \
        } else {                                \
            overflow = 0;                       \
            *(r) = xa + xb;                     \
        }                                       \
                                                \
        overflow;                               \
    })

#define XPOW2P(v)                               \
    ({                                          \
        __typeof((v)) _v = (v);                 \
        (_v & (_v-1)) == 0;                     \
    })

struct iovec;
size_t iovec_sum(const struct iovec* iov, unsigned niovec);

enum blocking_mode { blocking, non_blocking };
enum blocking_mode fd_set_blocking_mode(int fd, enum blocking_mode mode);

void hack_reopen_tty(int fd);
size_t read_all(int fd, void* buf, size_t sz);
void write_all(int fd, const void* buf, size_t sz);

#ifndef HAVE_DUP3
int dup3(int oldfd, int newfd, int flags);
#endif

#ifndef HAVE_PPOLL
int ppoll(struct pollfd *fds, nfds_t nfds,
          const struct timespec *timeout_ts,
          const sigset_t *sigmask);
#endif

#ifndef HAVE_MKOSTEMP
int mkostemp(char *template, int flags);
#endif

FILE* xnamed_tempfile(const char** name);

#ifndef _POSIX_VDISABLE
#define _POSIX_VDISABLE 0
#endif

void replace_with_dev_null(int fd);

