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
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <regex.h>
#include "dbg.h"

#ifndef ECOMM
#define ECOMM EBADRPC
#endif

#define ERR_ERRNO_WAS_ZERO -1
#define ERR_DEFERRED -2
#define ERR_QUIT_SIGNAL_FIRST -10
#define ERR_QUIT_SIGNAL_LAST -100
#define ERR_APP_BASE -1000

#define ARRAYSIZE(ar) (sizeof (ar) / sizeof (*(ar)))

// Suppress compiler warning about unused computation
static inline bool verify_dummy(bool x) { return x; }

#ifdef NDEBUG
# define VERIFY(x) (verify_dummy(x))
#else
# define VERIFY(x) (assert(x))
#endif

// Reslists own resources (or more precisely, they contain lists of
// cleanup closures).  Every time we allocate a resource, we mark it
// owned by the reslist named by _reslist_current.  reslist deallocate
// their owned resources when they are destroyed.  Scoped reslists are
// automatically destroyed when they go out of scope.  They go out of
// scope either on normal return (in which case the compiler runs the
// cleanup) or on die(), in which case the reslist machiney takes care
// of running the cleanups.
//
// The only operations that can affect the _reslist_current are
// SCOPED_RESLIST and WITH_CURRENT_RESLIST.

typedef void (*cleanupfn)(void* data);

struct resource {
    enum { RES_RESLIST_ONHEAP, RES_RESLIST_ONSTACK, RES_CLEANUP } type;
    // Circular list
    struct resource* prev;
    struct resource* next;
};

struct reslist {
    struct resource r;
    struct reslist* parent;
    struct resource head;
};

struct cleanup {
    struct resource r;
    cleanupfn fn;
    void* fndata;
};

// Create a new reslist owned by _reslist_current.
// Does _not_ make the new reslist current.
struct reslist* reslist_create(void);

// Destroy a reslist.  Cleans up all resources owned by that reslist.
void reslist_destroy(struct reslist* rl);

// Transfer resources owned by resist DONOR to reslist RECIPIENT.
// DONOR's resources are spliced in-order to the head of RECIPIENT.
// That is, when RECIPIENT is destroyed, all of DONOR's resources are
// cleaned up, and then all of RECIPIENT's.
void reslist_xfer(struct reslist* recipient, struct reslist* donor);

// Detach reslist RL from its current parent and move it to the
// current reslist.  reslist RL must be a heap-allocated reslist, as
// stack-allocated reslists (i.e., SCOPED_RESLIST) cannot be moved.
void reslist_reparent(struct reslist* rl);

void _reslist_scoped_push(struct reslist* rl);
void _reslist_scoped_pop(struct reslist* rl);

void _reslist_guard_push(struct reslist** saved_rl, struct reslist* rl);
void _reslist_guard_pop(struct reslist** saved_rl);

#define PASTE0(a,b) a##b
#define PASTE(a,b) PASTE0(a, b)
#define GENSYM(sym) PASTE(sym, __LINE__)

#define SCOPED_RESLIST(varname)                                 \
    __attribute__((cleanup(_reslist_scoped_pop)))               \
    struct reslist PASTE(varname,_reslist_);                    \
    struct reslist* varname = &PASTE(varname,_reslist_);        \
    _reslist_scoped_push(varname)

#define WITH_CURRENT_RESLIST(_rl)                               \
    __attribute__((cleanup(_reslist_guard_pop)))                \
    struct reslist* GENSYM(_reslist_saved);                     \
    _reslist_guard_push(&GENSYM(_reslist_saved), (_rl))

// Each resource owned by a reslist is associated with a cleanup
// function.  Adding a cleanup function requires allocating memory and
// can fail.  To make sure we can clean up every resource we allocate,
// we allocate a cleanup *before* the resource it owns, allocate the
// resource, and commit the cleanup object to that resource.
// The commit operation cannot fail.

// Allocate a new cleanup object. The storage for the cleanup object
// itself is owned by the current reslist (and is heap-allocated, and
// so can fail), but the new cleanup owns no resource.
struct cleanup* cleanup_allocate(void);

// Commit the cleanup object to a resource.  The cleanup object must
// have been previously allocated with cleanup_allocate.  A given
// cleanup object can be committed to a resource once.  When a cleanup
// object is allocated to a resource, it is re-inserted at the head of
// the current reslist.  Reslists clean up their resources in reverse
// order of insertion.
void cleanup_commit(struct cleanup* cl, cleanupfn fn, const void* fndata);

// Deregister and deallocate the given cleanup object CL, but do not
// run any cleanup functions to which CL may have been committed.
// If CL is NULL, do nothing.
void cleanup_forget(struct cleanup* cl);

// Allocate memory owned by the current reslist.
__attribute__((malloc))
void* xalloc(size_t sz);
__attribute__((malloc))
void* xcalloc(size_t sz);

// Like realloc(3), except that ptr!=NULL && size==0 means to reduce
// to size 1, not free the memory.
void* resize_alloc(void* ptr, size_t size);

// Code that fails calls die() or one of its variants below.
// Control then flows to the nearest enclosing catch_error.

typedef struct errinfo {
    int err;
    const char* msg;
    const char* prgname;
    unsigned want_msg : 1;
} errinfo;

#ifdef NDEBUG
# define ERRINFO_WANT_MSG_IF_DEBUG { 0 }
#else
# define ERRINFO_WANT_MSG_IF_DEBUG { .want_msg = true }
#endif

// Call FN with FNDATA with an internal resource list as current.
// If FN returns normally, transfer resources added to that resource
// list to the resource list that was current at the time of
// catch_error.  On error, destroy the resource list.  Return false on
// normal return or true on error.  If EI is non-null, fill it on
// error.  Strings are allocated on the resource list in effect at the
// time catch_error is called.  If want_msg is zero, error strings are
// not allocated, but ei->err is still set.
bool catch_error(void (*fn)(void* fndata),
                 void* fndata,
                 struct errinfo* ei);

// Like catch_error, but return true only in the case
// that we get an error matching ERRNUM; otherwise, rethrow.
bool catch_one_error(
    void (*fn)(void* fndata),
    void* fndata,
    int errnum);

typedef void (*error_converter)(int err, void* data);

// Install a function that we call before we dying.  If one of the
// error converter callbacks dies, we die with that error instead of
// the original.  An error converter is associated with the reslist in
// place at the time of its installation.  Error converters for
// reslists above the lowest catch_level are not called when dying,
// although they will be called if that catch_error returns and we die
// again (up to the next catch_error).
void install_error_converter(error_converter ec, void* ecdata);

__attribute__((noreturn))
void die_rethrow(struct errinfo* ei);

void check_deferred_errors(void);

__attribute__((format(printf,2,3)))
void deferred_die(int err, const char* fmt, ...);

__attribute__((noreturn))
void diev(int err, const char* fmt, va_list args);
__attribute__((noreturn,format(printf, 2, 3)))
void die(int err, const char* fmt, ...);
__attribute__((noreturn,format(printf, 1, 2)))
void die_errno(const char* fmt, ...);
__attribute__((noreturn))
void die_oom(void);

__attribute__((malloc,format(printf, 1, 2)))
char* xaprintf(const char* fmt, ...);
__attribute__((malloc))
char* xavprintf(const char* fmt, va_list args);
__attribute__((malloc))
char* xstrdup(const char* s);
char* xstrndup(const char* s, size_t nr);

bool error_temporary_p(int errnum);

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

#ifndef _POSIX_VDISABLE
#define _POSIX_VDISABLE 0
#endif

void* generate_random_bytes(size_t howmany);
char* hex_encode_bytes(const void* bytes, size_t n);
char* gen_hex_random(size_t nr_bytes);

void* first_non_null(void* s, ...);
bool string_starts_with_p(const char* string, const char* prefix);
bool string_ends_with_p(const char* string, const char* suffix);

#ifdef HAVE_CLOCK_GETTIME
double xclock_gettime(clockid_t clk_id);
#endif

double seconds_since_epoch(void);

extern sigset_t signals_unblock_for_io;
extern sigset_t orig_sigmask;
extern sigset_t orig_sig_ignored;
extern int signal_quit_in_progress;

void _unblock_io_unblocked_signals(sigset_t* saved);
void _restore_io_unblocked_signals(sigset_t* saved);

#define WITH_IO_SIGNALS_ALLOWED()                                       \
    __attribute__((cleanup(_restore_io_unblocked_signals)))             \
    sigset_t GENSYM(_saved_signals);                                    \
    _unblock_io_unblocked_signals(&GENSYM(_saved_signals))

void save_signals_unblock_for_io(void);
void sigaction_restore_as_cleanup(int signo, struct sigaction* sa);

// Like execvpe, but actually works on bionic.  Die on error.
// Not async-signal-safe.  Signal handlers and dispositions are reset
// to their original (as defined by orig_sigmask and orig_sig_ignored)
// values before the exec and restored before dieing if the
// exec fails.
__attribute__((noreturn))
void xexecvpe(const char* file,
              const char* const* argv,
              const char* const* envp);

__attribute__((noreturn))
void xexecvp(const char* file, const char* const* argv);

struct sigtstp_cookie;
enum sigtstp_mode {
    SIGTSTP_BEFORE_SUSPEND,
    SIGTSTP_AFTER_RESUME,
    SIGTSTP_AFTER_UNEXPECTED_SIGCONT,
};

typedef void (*sigtstp_callback)(
    enum sigtstp_mode mode,
    void* data);

struct sigtstp_cookie* sigtstp_register(sigtstp_callback cb, void* cbdata);
void sigtstp_unregister(struct sigtstp_cookie* cookie);

typedef void (*sigio_callback)(void* data);
struct sigio_cookie;
struct sigio_cookie* sigio_register(sigio_callback cb, void* cbdata);
void sigio_unregister(struct sigio_cookie* cookie);

// Set an itimer timeout.  Blocks SIGALRM except inside IO.  If we get
// a SIGALRM, raise a die-exception from IO context.  Restore signals
// and timer on unwind.
void set_timeout(const struct itimerval* timer, int err, const char* msg);
// Set a timeout in milliseconds; if ms is negative, do not set
// a timeout.
void set_timeout_ms(int ms, int err, const char* msg);

// When set, die when receiving a quit signal instead of trying to
// unwind reslists immediately; used inside fs.c stdio integration.
extern bool hack_die_on_quit;

unsigned api_level(void);

const char* my_exe(void);
const char* maybe_my_exe(const char* exename);

void become_daemon(void (*daemon_setup)(void* setup_data),
                   void* setup_data);

bool clowny_output_line_p(const char* line);

// Destructively remove characters in SET from the end of STRING.
// If STRINGSZ_INOUT is non-NULL, it is in bytes the length of STRING
// in bytes, not including the terminating NUL.
void rtrim(char* string, size_t* stringsz_inout, const char* set);

// struct growable_buffer users should zero-initialize instances.

struct growable_buffer {
    struct cleanup* cl;
    uint8_t* buf;
    size_t bufsz;
};

void resize_buffer(struct growable_buffer* gb, size_t new_size);
void grow_buffer(struct growable_buffer* gb, size_t min);
void grow_buffer_dwim(struct growable_buffer* gb);

regex_t* xregcomp(const char* regex, int cflags);
char* xregerror(int errcode, const regex_t* preg);

// Plain stdio operations on standard stream FILE* don't unblock
// signals around IO.  We can't portably replace the stdio streams,
// but we can ban their use.

#ifndef EVADE_STDIO_BAN
# ifdef puts
#  undef puts
# endif
# define puts(...) ERROR_see_util_h
# ifdef putchar
#  undef putchar
# endif
# define putchar(...) ERROR_see_util_h
# ifdef printf
#  undef printf
# endif
# define printf(...) ERROR_see_util_h
# ifdef stdin
#  undef stdin
# endif
# define stdin ERROR_see_util_h
# ifdef stdout
#  undef stdout
# endif
# define stdout ERROR_see_util_h
# ifdef stderr
#  undef stderr
# endif
# define stderr ERROR_see_util_h
#endif

extern FILE* xstdin;
extern FILE* xstdout;
extern FILE* xstderr;

extern char** environ;
