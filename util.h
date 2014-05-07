#pragma once
#include <stdarg.h>
#include <stddef.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include "dbg.h"

#define ARRAYSIZE(ar) (sizeof (ar) / sizeof (*(ar)))

struct reslist;
struct reslist* reslist_push_new(void);
void reslist_cleanup_local(struct reslist** rl_local);
void reslist_pop_nodestroy(void);
void reslist_destroy(struct reslist* rl);

#define SCOPED_RESLIST(varname)                         \
    __attribute__((cleanup(reslist_cleanup_local)))     \
    struct reslist* varname = reslist_push_new();

typedef void (*cleanupfn)(void* data);
struct cleanup;
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

struct iovec;
size_t iovec_sum(const struct iovec* iov, unsigned niovec);

enum blocking_mode { blocking, non_blocking };
enum blocking_mode fd_get_blocking_mode(int fd);
enum blocking_mode fd_set_blocking_mode(int fd, enum blocking_mode mode);

void hack_reopen_tty(int fd);

