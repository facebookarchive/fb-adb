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

#define EVADE_STDIO_BAN 1

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <setjmp.h>
#include <stdlib.h>
#ifdef HAVE_FEATURES_H
# include <features.h>
#endif
#include <signal.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <libgen.h>
#include "fs.h"
#include "valgrind.h"

#ifndef LIST_FOREACH_SAFE
#define LIST_FOREACH_SAFE(var, head, field, next_var)           \
    for ((var) = ((head)->lh_first);                            \
         (var) && (((next_var) = ((var)->field.le_next)), 1);   \
         (var) = (next_var))
#endif

#if !defined(HAVE_EXECVPE)
# include <paths.h>
#endif

#ifdef HAVE_SIGNALFD_4
# include <sys/signalfd.h>
#endif

#ifdef __ANDROID__
# include <sys/system_properties.h>
#endif

#include "util.h"
#include "constants.h"

struct error_converter_record {
    LIST_ENTRY(error_converter_record) link;
    error_converter ec;
    void* ecdata;
    bool onlist;
};

struct errhandler {
    sigjmp_buf where;
    struct reslist* rl;
    struct errinfo* ei;
    int deferred_error;
    LIST_HEAD(,error_converter_record) error_converters;
};

static struct reslist reslist_top;
static struct reslist* _reslist_current;
static struct errhandler* current_errh;
const char* prgname;
const char* orig_argv0;

FILE* xstdin;
FILE* xstdout;
FILE* xstderr;

sigset_t signals_unblock_for_io;
sigset_t orig_sigmask;
sigset_t orig_sig_ignored;
int signal_quit_in_progress;
bool hack_die_on_quit;

static void sigio_sigaction(int, siginfo_t*, void*);

static bool
reslist_empty_p(struct reslist* rl)
{
    return rl->head.next == &rl->head;
}

static struct resource*
reslist_first(struct reslist* rl)
{
    return rl->head.next;
}

static void
reslist_insert_after(struct resource* pos, struct resource* r)
{
    assert(r->prev == NULL);
    assert(r->next == NULL);
    r->prev = pos;
    r->next = pos->next;
    pos->next = r;
    r->next->prev = r;
}

// Assert that reslist RL is not CHECK or any parent of CHECK.
static void
assert_not_parent(struct reslist* rl, struct reslist* check)
{
#ifndef NDEBUG
    do {
        assert(rl != check);
    } while ((check = check->parent));
#endif
}

static void
reslist_insert_head(struct reslist* rl, struct resource* r)
{
#ifndef NDEBUG
    if (r->type == RES_RESLIST_ONHEAP ||
        r->type == RES_RESLIST_ONSTACK)
    {
        assert_not_parent((struct reslist*) r, rl);
    }
#endif

    reslist_insert_after(&rl->head, r);
}

static void
reslist_init(struct reslist* rl, struct reslist* parent, int type)
{
    memset(rl, 0, sizeof (*rl));
    rl->r.type = type;
    rl->head.prev = rl->head.next = &rl->head;
    if (parent) {
        rl->parent = parent;
        reslist_insert_head(parent, &rl->r);
    }
}

static void
reslist_remove(struct resource* r)
{
    assert(r->prev != NULL);
    assert(r->next != NULL);
    r->prev->next = r->next;
    r->next->prev = r->prev;
#ifndef NDEBUG
    r->prev = r->next = NULL;
#endif
}

static void
cleanup_destroy(struct cleanup* cl)
{
    reslist_remove(&cl->r);
    if (cl->fn)
        (cl->fn)(cl->fndata);

    free(cl);
}

static void
empty_reslist(struct reslist* rl)
{
    // Reset current_errh to NULL so that failures inside cleanups are
    // fatal --- just like throwing an exception in a destructor in
    // C++.  Cleanups can use catch_error internally because
    // catch_error saves, sets, and restores current_errh as well.
    struct errhandler* saved_errh = current_errh;
    current_errh = NULL;

    while (!reslist_empty_p(rl)) {
        struct resource* r = reslist_first(rl);
        if (r->type == RES_RESLIST_ONHEAP
            || r->type == RES_RESLIST_ONSTACK)
        {
            reslist_destroy((struct reslist*) r);
        } else {
            cleanup_destroy((struct cleanup*) r);
        }
    }

    current_errh = saved_errh;
}

// GCC can't prove to itself that stack allocations are always tagged
// with RES_RESLIST_ONSTACK, not RES_RESLIST_ONHEAP, and so warns that
// the call to free(3) below might be trying to free stack memory.

void
reslist_destroy(struct reslist* rl)
{
    empty_reslist(rl);
    reslist_remove(&rl->r);
    if (rl->r.type == RES_RESLIST_ONHEAP)
        free(rl);
}

struct reslist*
reslist_create(void)
{
    struct reslist* rl = malloc(sizeof (*rl));
    if (rl == NULL)
        die_oom();
    reslist_init(rl, _reslist_current, RES_RESLIST_ONHEAP);
    return rl;
}

void
_reslist_scoped_push(struct reslist* rl)
{
    reslist_init(rl, _reslist_current, RES_RESLIST_ONSTACK);
    _reslist_current = rl;
}

void
_reslist_scoped_pop(struct reslist* rl)
{
    _reslist_current = rl->parent;
    reslist_destroy(rl);
}

void
_reslist_guard_push(struct reslist** saved_rl, struct reslist* rl)
{
    *saved_rl = _reslist_current;
    _reslist_current = rl;
}

void
_reslist_guard_pop(struct reslist** saved_rl)
{
    _reslist_current = *saved_rl;
}


void
reslist_xfer(struct reslist* recipient, struct reslist* donor)
{
    assert_not_parent(donor, recipient);
    if (!reslist_empty_p(donor)) {
        struct resource* donor_first = donor->head.next;
        struct resource* donor_last = donor->head.prev;

        assert(donor_first->prev == &donor->head);
        assert(donor_last->next == &donor->head);
        assert(donor->head.next != &donor->head);
        assert(donor->head.prev != &donor->head);

        donor_last->next = recipient->head.next;
        donor_first->prev = &recipient->head;
        donor_last->next->prev = donor_last;
        donor_first->prev->next = donor_first;
        donor->head.next = donor->head.prev = &donor->head;
    }
}

void
reslist_reparent(struct reslist* rl)
{
    assert(rl->r.type == RES_RESLIST_ONHEAP);
    assert_not_parent(rl, _reslist_current);
    reslist_remove(&rl->r);
    reslist_insert_head(_reslist_current, &rl->r);
}

struct cleanup*
cleanup_allocate(void)
{
    struct cleanup* cl = calloc(1, sizeof (*cl));
    if (cl == NULL)
        die_oom();

    cl->r.type = RES_CLEANUP;
    reslist_insert_head(_reslist_current, &cl->r);
    return cl;
}

void*
resize_alloc(void* ptr, size_t size)
{
    return realloc(ptr, size ?: 1);
}

void
cleanup_commit(struct cleanup* cl,
               cleanupfn fn,
               const void* fndata)
{
    // Regardless of where the structure was when we allocated it, put
    // it on top of the stack now.
    assert(cl->fn == NULL);
    cl->fn = fn;
    cl->fndata = (void*) fndata;
    reslist_remove(&cl->r);
    reslist_insert_head(_reslist_current, &cl->r);
}

void
cleanup_forget(struct cleanup* cl)
{
    if (cl != NULL) {
        cl->fn = NULL;
        cleanup_destroy(cl);
    }
}

void
check_deferred_errors(void)
{
    if (current_errh->deferred_error) {
        int err = current_errh->deferred_error;
        current_errh->deferred_error = 0;
        struct errinfo* ei = current_errh->ei;
        const char* errmsg = (ei && ei->msg) ? ei->msg : "deferred error";
        die(err, "%s", errmsg);
    }
}

static void
delist_error_converters(void)
{
    while (!LIST_EMPTY(&current_errh->error_converters)) {
        struct error_converter_record* ecr =
            LIST_FIRST(&current_errh->error_converters);
        LIST_REMOVE(ecr, link);
        ecr->onlist = false;
    }
}

bool
catch_error(void (*fn)(void* fndata),
            void* fndata,
            struct errinfo* ei)
{
    SCOPED_RESLIST(rl);
    bool error = true;
    struct errhandler* old_errh = current_errh;
    struct errhandler errh;
    memset(&errh, 0, sizeof (errh));
    errh.rl = rl;
    errh.ei = ei;
    LIST_INIT(&errh.error_converters);
    current_errh = &errh;
    if (sigsetjmp(errh.where, 1) == 0) {
        fn(fndata);
        // Not reached on success: on error, we jump to the
        // __sync_synchronize below.
        check_deferred_errors();
        reslist_xfer(rl->parent, rl);
        delist_error_converters();
        error = false;
    } else {
        __sync_synchronize();
    }

    current_errh = old_errh;
    return error;
}

bool
catch_one_error(
    void (*fn)(void* fndata),
    void* fndata,
    int errnum)
{
    struct errinfo ei = {
        .want_msg = true
    };

    if (catch_error(fn, fndata, &ei)) {
        if (ei.err == errnum)
            return true;
        die_rethrow(&ei);
    }
    return false;
}

void
die_rethrow(struct errinfo* ei)
{
    die(ei->err, "%s", ei->msg);
}

char*
xavprintf(const char* fmt, va_list args)
{
    va_list args2;
    va_copy(args2, args);
    int n = vsnprintf(NULL, 0, fmt, args2);
    va_end(args2);
    if (n < 0)
        die(EINVAL, "invalid format string %.80s", fmt);

    size_t buflen = (size_t) n + 1;
    char* buf = xalloc(buflen);
    vsnprintf(buf, buflen, fmt, args);
    return buf;
}

char*
xaprintf(const char* fmt, ...)
{
    va_list args;
    char* result;
    va_start(args, fmt);
    result = xavprintf(fmt, args);
    va_end(args);
    return result;
}

void*
xalloc(size_t sz)
{
    struct cleanup* cl = cleanup_allocate();
    void* mem = malloc(sz);
    if (mem == NULL)
        die_oom();

    cleanup_commit(cl, free, mem);
    return mem;
}

void*
xcalloc(size_t sz)
{
    void* mem = xalloc(sz);
    memset(mem, 0, sz);
    return mem;
}

void
die_oom(void)
{
    if (current_errh == NULL)
        abort();

    assert(current_errh);
    if (current_errh->ei) {
        current_errh->ei->err = ENOMEM;
        current_errh->ei->msg = "no memory";
    }

    empty_reslist(current_errh->rl);
    siglongjmp(current_errh->where, 1);
}

static void
error_converter_cleanup(void* data)
{
    struct error_converter_record* ecr = data;
    if (ecr->onlist)
        LIST_REMOVE(ecr, link);
    free(ecr);
}

void
install_error_converter(error_converter ec, void* ecdata)
{
    struct cleanup* cl = cleanup_allocate();
    struct error_converter_record* ecr = calloc(1, sizeof (*ecr));
    if (ecr == NULL)
        die_oom();
    ecr->ec = ec;
    ecr->ecdata = ecdata;
    ecr->onlist = true;
    LIST_INSERT_HEAD(&current_errh->error_converters, ecr, link);
    cleanup_commit(cl, error_converter_cleanup, ecr);
}

struct try_xavprintf_ctx {
    const char* fmt;
    va_list args;
    char* result;
};

static void
try_xavprintf_1(void* data)
{
    struct try_xavprintf_ctx* ctx = data;
    ctx->result = xavprintf(ctx->fmt, ctx->args);
}

void
deferred_die(int err, const char* fmt, ...)
{
    if (current_errh == NULL)
        abort();

    err = err ?: ERR_ERRNO_WAS_ZERO;

    struct errinfo* ei = current_errh->ei;
    if (ei) {
        ei->err = err;
        if (ei->want_msg) {
            WITH_CURRENT_RESLIST(current_errh->rl->parent);

            struct try_xavprintf_ctx ctx;
            memset(&ctx, 0, sizeof (ctx));
            ctx.fmt = fmt;
            va_start(ctx.args, fmt);
            if (!catch_error(try_xavprintf_1, &ctx, ei))
                ei->msg = ctx.result;
            va_end(ctx.args);
        }
    }
    current_errh->deferred_error = err;
}

void
diev(int err, const char* fmt, va_list args)
{
    if (current_errh == NULL)
        abort();

    check_deferred_errors();

    {
        // Give pending signals a chance to propagate in case we're
        // dying due to a failure ultimately caused by a
        // pending signal.
        // N.B. Keep in mind constants are negative in range check
        WITH_IO_SIGNALS_ALLOWED();
        if (!hack_die_on_quit &&
            ERR_QUIT_SIGNAL_LAST <= err && err <= ERR_QUIT_SIGNAL_FIRST)
        {
            raise(ERR_QUIT_SIGNAL_FIRST - err);
        }
    }

    if (err == 0)
        err = ERR_ERRNO_WAS_ZERO;

    if (current_errh->ei) {
        struct errinfo* ei = current_errh->ei;
        ei->err = err;

        while (!LIST_EMPTY(&current_errh->error_converters)) {
            struct error_converter_record* ecr =
                LIST_FIRST(&current_errh->error_converters);
            LIST_REMOVE(ecr, link);
            ecr->onlist = false;
            ecr->ec(err, ecr->ecdata);
        }

        if (ei->want_msg) {
            WITH_CURRENT_RESLIST(current_errh->rl->parent);
            // die_oom will DTRT on alloc failure.
            ei->msg = xavprintf(fmt, args);
            ei->prgname = xstrdup(prgname);
        }
    }

    empty_reslist(current_errh->rl);
    siglongjmp(current_errh->where, 1);
}

void
die(int err, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    diev(err, fmt, args);
}

void
die_errno(const char* fmt, ...)
{
    int e = errno;
    va_list args;
    va_start(args, fmt);
    die(e, "%s: %s", xavprintf(fmt, args), strerror(e));
}

bool
error_temporary_p(int errnum)
{
    return (errnum == EINTR ||
            errnum == EAGAIN ||
            errnum == EWOULDBLOCK);
}

struct main_info {
    int argc;
    char** argv;
    int ret;
};

static void
handle_quit_signal(int signum)
{
    signal_quit_in_progress = signum;
    if (hack_die_on_quit)
        die(ERR_QUIT_SIGNAL_FIRST - signum, "quit");

    empty_reslist(&reslist_top);
    sigset_t our_signal;
    VERIFY(sigemptyset(&our_signal) == 0);
    VERIFY(sigaddset(&our_signal, signum) == 0);
    VERIFY(sigprocmask(SIG_UNBLOCK, &our_signal, NULL) == 0);
    // SA_RESETHAND ensures that we run the default handler here
    raise(signum);
    abort();
}

static void
quit_signal_sigaction(int signum, siginfo_t* info, void* context)
{
    handle_quit_signal(signum);
}

static void job_control_signal_sigaction(int, siginfo_t*,void*);

static void
handle_sigchld(int signo)
{
    // Noop: we just need any handler
}

__attribute__((unused))
static void
make_line_buffered(FILE* stream)
{
    if (setvbuf(stream, NULL, _IOLBF, 0) != 0)
        die_errno("setvbuf");
}

__attribute__((unused))
static const char*
xsigname(int signo)
{
    return xaprintf("signal %d (%s)", signo, strsignal(signo) ?: "?");
}

#define INIT_SIGNALS_RESET (1<<0)

static void
init_signals(int flags)
{
    // Give us a chance to do any critical cleanups before terminating
    // due to a fatal signal.  The handlers run only in
    // WITH_IO_SIGNALS_ALLOWED regions.  These regions can contain
    // only pure system calls (because we say so) and do not have any
    // locks held (because we say so), so handlers run in these
    // regions have full access to the heap, the cleanup list, and
    // other process-wide facilities.

    int quit_signals[] = {
        SIGHUP, SIGINT, SIGQUIT, SIGTERM
    };

    int job_control_signals[] = { SIGCONT, SIGTSTP, SIGTTIN, SIGTTOU };

    sigset_t to_block_mask;
    sigemptyset(&to_block_mask);
    for (int i = 0; i < ARRAYSIZE(quit_signals); ++i)
        sigaddset(&to_block_mask, quit_signals[i]);
    for (int i = 0; i < ARRAYSIZE(job_control_signals); ++i)
        sigaddset(&to_block_mask, job_control_signals[i]);
    sigaddset(&to_block_mask, SIGIO);

    // See the big comment in child.c's child_wait.
    VERIFY(signal(SIGCHLD, handle_sigchld) != SIG_ERR);
    sigaddset(&to_block_mask, SIGCHLD);

    if (flags & INIT_SIGNALS_RESET) {
        sigemptyset(&orig_sigmask);
        VERIFY(sigprocmask(SIG_SETMASK, &to_block_mask, NULL) == 0);
        for (int signo = 1; signo < NSIG; ++signo)
            if (sigismember(&orig_sig_ignored, signo))
                VERIFY(signal(signo, SIG_DFL) != SIG_ERR);
        sigemptyset(&orig_sig_ignored);
    } else {
        VERIFY(sigprocmask(SIG_BLOCK, &to_block_mask, &orig_sigmask) == 0);
    }

    sigset_t all_signals_mask;
    VERIFY(sigfillset(&all_signals_mask) == 0);

    for (int i = 0; i < ARRAYSIZE(quit_signals); ++i) {
        int sig = quit_signals[i];
        struct sigaction sa;
        memset(&sa, 0, sizeof (sa));
        sa.sa_sigaction = quit_signal_sigaction;
        sa.sa_mask = all_signals_mask;
        sa.sa_flags = SA_RESETHAND | SA_SIGINFO;
        VERIFY(sigaction(sig, &sa, NULL) == 0);
        // Only unblock signals that were unblocked when we started
        if (sigismember(&orig_sigmask, sig)) {
            dbg("will not unblocking %s during IO: "
                "blocked on startup",
                xsigname(sig));
        } else if (sigismember(&orig_sig_ignored, sig)) {
            dbg("will not be unblocking %s during IO: ignored on startup",
                xsigname(sig));
        } else {
            sigaddset(&signals_unblock_for_io, sig);
        }
    }

    for (int i = 0; i < ARRAYSIZE(job_control_signals); ++i) {
        struct sigaction sa;
        memset(&sa, 0, sizeof (sa));
        sa.sa_sigaction = job_control_signal_sigaction;
        sa.sa_mask = all_signals_mask;
        sa.sa_flags = SA_SIGINFO;
        VERIFY(sigaction(job_control_signals[i], &sa, NULL) == 0);
        sigaddset(&signals_unblock_for_io, job_control_signals[i]);
    }

    {
        struct sigaction sa;
        memset(&sa, 0, sizeof (sa));
        sa.sa_sigaction = sigio_sigaction;
        sa.sa_flags = SA_SIGINFO;
        VERIFY(sigaction(SIGIO, &sa, NULL) == 0);
        sigaddset(&signals_unblock_for_io, SIGIO);
    }
}

void
main1(void* arg)
{
    struct main_info* mi = arg;

#ifndef DISABLE_SAFE_STDIO
    {
        WITH_CURRENT_RESLIST(&reslist_top);
        xstdin = xfdopen(STDIN_FILENO, "r");
        xstdout = xfdopen(STDOUT_FILENO, "w");
        xstderr = xfdopen(STDERR_FILENO, "w");
        if (isatty(STDOUT_FILENO))
            make_line_buffered(xstdout);
        make_line_buffered(xstderr);
    }
#endif

#ifndef NDEBUG
    for (int sig = 1; sig < NSIG; ++sig)
        if (sigismember(&orig_sig_ignored, sig))
            dbg("signal %s ignored at startup: will ignore in children",
                xsigname(sig));
#endif

    init_signals(0);
    _fs_on_init();
    mi->ret = real_main(mi->argc, mi->argv);

    xflush(xstdout);
    xflush(xstderr);
}

static void
print_toplevel_error(void* data)
{
    struct errinfo* ei = data;
    const char* pnam = ei->prgname;
    const char* sep = pnam[0] ? ": " : "";
    dbg("ERROR: %s%s%s", pnam, sep, ei->msg);
    xprintf(xstderr, "%s%s%s\n", pnam, sep, ei->msg);
    xflush(xstderr);
}

static void
try_flush_xstream(void* data)
{
    xflush((FILE*) data);
}

int
main(int argc, char** argv)
{
    for (int i = 1; i < NSIG; ++i) {
        struct sigaction orig_sa;
        if (sigaction(i, NULL, &orig_sa) == 0 &&
            (orig_sa.sa_flags & SA_SIGINFO) == 0 &&
            orig_sa.sa_handler == SIG_IGN)
        {
            sigaddset(&orig_sig_ignored, i);
        }
    }

    VERIFY(signal(SIGPIPE, SIG_IGN) != SIG_ERR);

    xstdin = stdin;
    xstdout = stdout;
    xstderr = stderr;

    struct main_info mi;
    mi.argc = argc;
    mi.argv = argv;

    reslist_init(&reslist_top, NULL, RES_RESLIST_ONSTACK);
    _reslist_current = &reslist_top;

    prgname = argv[0];
    dbg_init();
    dbglock_init();
    orig_argv0 = argv[0];
    prgname = xbasename(argv[0]);
    const char* orig_prgname = prgname;
    struct errinfo ei = { .want_msg = true };
    if (catch_error(main1, &mi, &ei)) {
        if (ei.prgname == NULL)
            ei.prgname = orig_prgname;
        mi.ret = 1;
        (void) catch_error(try_flush_xstream, xstdout, NULL);
        (void) catch_error(try_flush_xstream, xstderr, NULL);
        // We shouldn't complain about perfectly reasonable failures
        // writing to broken output streams.
        if (ei.err == EPIPE &&
            (string_starts_with_p(ei.msg, "write(1): ") ||
             string_starts_with_p(ei.msg, "write(2): ")))
        {
            dbg("ignoring EPIPE on standard stream");
        } else {
            (void) catch_error(print_toplevel_error, &ei, NULL);
        }
    }

    empty_reslist(&reslist_top);
    return mi.ret;
}

// Round up to next power of two.  If zero given as input, return 0.
// If number too large to fit, return 0.
size_t
nextpow2sz(size_t sz)
{
    sz -= 1;
    sz |= sz >> 1;
    sz |= sz >> 2;
    sz |= sz >> 4;
    sz |= sz >> 8;
    sz |= sz >> 16;
#if UINT_MAX != SIZE_MAX
    sz |= sz >> 32;
#endif

    return 1 + sz;
}

char*
xstrdup(const char* s)
{
    return xaprintf("%s", s);
}

char*
xstrndup(const char* s, size_t n)
{
    size_t nslen = strnlen(s, n);
    char* ns = xalloc(nslen+1);
    memcpy(ns, s, nslen);
    ns[nslen] = '\0';
    return ns;
}

static void
cleanup_prgname(void* arg)
{
    prgname = arg;
}

void
set_prgname(const char* s)
{
    struct cleanup* c = cleanup_allocate();
    cleanup_commit(c, cleanup_prgname, (void*) prgname);
    prgname = s;
}

size_t
iovec_sum(const struct iovec* iov, unsigned niovec)
{
    size_t total = 0;
    for (unsigned i = 0; i < niovec; ++i)
        total += iov[i].iov_len;

    return total;
}

void*
generate_random_bytes(size_t howmany)
{
    void* buffer = xalloc(howmany);
    SCOPED_RESLIST(rl);
    int ufd = xopen("/dev/urandom", O_RDONLY, 0);
    size_t nr_read = read_all(ufd, buffer, howmany);
    if (nr_read < howmany)
        die(EINVAL, "too few bytes from random device");

    return buffer;
}

char*
hex_encode_bytes(const void* bytes_in, size_t nr_bytes)
{
    const uint8_t* bytes = (const uint8_t*) bytes_in;
    size_t nr_encoded_bytes = nr_bytes;
    if (SATADD(&nr_encoded_bytes, nr_encoded_bytes, nr_bytes) ||
        SATADD(&nr_encoded_bytes, nr_encoded_bytes, 1))
    {
        die(ERANGE, "nr_bytes too big");
    }

    char* buffer = xalloc(nr_encoded_bytes);
    for (size_t i = 0; i < nr_bytes; ++i) {
        sprintf(buffer + i*2, "%x%x",
                bytes[i] >> 4,
                bytes[i] & 0xF);
    }

    buffer[nr_encoded_bytes - 1] = '\0';
    return buffer;
}

char*
gen_hex_random(size_t nr_bytes)
{
    return hex_encode_bytes(generate_random_bytes(nr_bytes), nr_bytes);
}

void*
first_non_null(void* s, ...)
{
    void* ret = s;
    va_list args;
    va_start(args, s);

    while (ret == NULL)
        ret = va_arg(args, void*);

    va_end(args);
    return ret;
}

bool
string_starts_with_p(const char* string, const char* prefix)
{
    return strncmp(string, prefix, strlen(prefix)) == 0;
}

bool
string_ends_with_p(const char* string, const char* suffix)
{
    size_t sl = strlen(string);
    size_t pl = strlen(suffix);
    return pl <= sl && memcmp(string + sl - pl, suffix, pl) == 0;
}

#ifdef HAVE_CLOCK_GETTIME
double
xclock_gettime(clockid_t clk_id)
{
    struct timespec ts;
    if (clock_gettime(clk_id, &ts) == -1)
        die_errno("clock_gettime");

    return (double) ts.tv_sec + (double) ts.tv_nsec / 1e9;
}
#endif

double
seconds_since_epoch(void)
{
    struct timeval tv;
    VERIFY(gettimeofday(&tv, NULL) == 0);
    return (double) tv.tv_sec + tv.tv_usec / 1e6;
}

void
str2gaiargs(const char* inp, char** node, char** service)
{
    const char* sep = strchr(inp, ',');
    if (sep == NULL)
        die(EINVAL, "bad network address \"%s\"", inp);

    *node = xstrndup(inp, sep - inp);
    *service = xstrdup(sep + 1);
}

void
_unblock_io_unblocked_signals(sigset_t* saved)
{
    if (!signal_quit_in_progress)
        VERIFY(!sigprocmask(SIG_UNBLOCK, &signals_unblock_for_io, saved));
}

void
_restore_io_unblocked_signals(sigset_t* saved)
{
    if (!signal_quit_in_progress)
        VERIFY(!sigprocmask(SIG_SETMASK, saved, NULL));
}


static void
cleanup_save_signals_unblock_for_io(void* data)
{
    dbg("restoring signals_unblock_for_io");
    memcpy(&signals_unblock_for_io, data, sizeof (sigset_t));
}

void
save_signals_unblock_for_io(void)
{
    struct cleanup* cl = cleanup_allocate();
    sigset_t* saved_signals_unblock_for_io =
        xalloc(sizeof (*saved_signals_unblock_for_io));

    memcpy(saved_signals_unblock_for_io,
           &signals_unblock_for_io,
           sizeof (sigset_t));

    cleanup_commit(
        cl,
        cleanup_save_signals_unblock_for_io,
        saved_signals_unblock_for_io);
}

struct cleanup_restore_sighandler {
    int signo;
    struct sigaction oldsa;
};

static void
cleanup_restore_sighandler(void* info)
{
    struct cleanup_restore_sighandler* cs = info;
    dbg("restoring sighandler");
    VERIFY(sigaction(cs->signo, &cs->oldsa, NULL) == 0);
}

void
sigaction_restore_as_cleanup(int signo, struct sigaction* sa)
{
    struct cleanup_restore_sighandler* cs = xalloc(sizeof (*cs));
    struct cleanup* cl = cleanup_allocate();
    cs->signo = signo;
    if (sigaction(signo, sa, &cs->oldsa) != 0)
        die_errno("sigaction");

    cleanup_commit(cl, cleanup_restore_sighandler, cs);
}

struct saved_signal_context {
    struct sigaction saved_handlers[NSIG];
    sigset_t saved_sigmask;
    sigset_t saved_signals;
};

static void
reset_orig_signal_context(struct saved_signal_context* ssc)
{
    memset(ssc, 0, sizeof (*ssc));
    sigemptyset(&ssc->saved_sigmask);
    sigemptyset(&ssc->saved_signals);

    for (int signo = 1; signo < NSIG; ++signo) {
        if (signo == SIGKILL || signo == SIGSTOP)
            continue; // Unblockable
#ifdef __linux__
        if (signo > SIGSYS && signo < SIGRTMIN)
            continue; // Internal to libc
#endif
        bool ignore = sigismember(&orig_sig_ignored, signo);
        struct sigaction newsa;
        memset(&newsa, 0, sizeof (newsa));
        newsa.sa_handler = ignore ? SIG_IGN : SIG_DFL;
        if (sigaction(signo, &newsa, &ssc->saved_handlers[signo]) == 0)
            sigaddset(&ssc->saved_signals, signo);
        else
            dbg("failed to save signal %d: %s", signo, strerror(errno));
    }
    (void) sigprocmask(SIG_SETMASK, &orig_sigmask, &ssc->saved_sigmask);
}

static void
restore_saved_signal_context(struct saved_signal_context* ssc)
{
    sigset_t all_signals;
    sigfillset(&all_signals);
    (void) sigprocmask(SIG_SETMASK, &all_signals, NULL);

    for (int signo = 1; signo < NSIG; ++signo) {
        if (!sigismember(&ssc->saved_signals, signo)) {
            dbg("signal %d was not saved; ignoring", signo);
            continue;
        }

        if (sigaction(signo, &ssc->saved_handlers[signo], NULL) != 0)
            abort();
    }

    (void) sigprocmask(SIG_SETMASK, &ssc->saved_sigmask, NULL);
}

#ifdef HAVE_EXECVPE
void
xexecvpe(const char* file,
         const char* const* argv,
         const char* const* envp)
{
    struct saved_signal_context ssc;
    reset_orig_signal_context(&ssc);
    execvpe(file,
            (char* const*) argv,
            (char* const*) envp);
    restore_saved_signal_context(&ssc);
    die_errno("execvpe(\"%s\")", file);
}
#else
static void
call_execve(const char* file,
            const char* const* argv,
            const char* const* envp)
{
    struct saved_signal_context ssc;
    reset_orig_signal_context(&ssc);
    (void) execve(file, (char* const*) argv, (char* const*) envp);
    restore_saved_signal_context(&ssc);
}

static void
try_execvpe_via_shell (const char* file,
                       const char* const* argv,
                       const char* const* envp)
{
    size_t argc = 0;
    for (const char* const* a = argv; *a; ++a)
        ++argc;

    size_t shell_argc = argc + 2;
    const char** shell_argv = xalloc(sizeof (char*) * (shell_argc + 1));
    shell_argv[0] = "sh";
    shell_argv[1] = file;
    memcpy(&shell_argv[2], argv, sizeof (char*) * (argc+1));
    call_execve(_PATH_BSHELL, shell_argv, envp);
}

void
xexecvpe(const char* file,
         const char* const* argv,
         const char* const* envp)
{
    // Of _course_ Bionic lacks execvpe(3).
    bool saw_eaccess = false;

    if (file == NULL || file[0] == '\0') {
        errno = ENOENT;
        goto done;
    }

    if (strchr(file, '/')) {
        call_execve(file, argv, envp);
        if (errno == ENOEXEC)
            try_execvpe_via_shell (file, argv, envp);
        goto done;
    }

    size_t file_length = strlen(file);
    const char* path = getenv("PATH") ?: _PATH_DEFPATH;
    errno = 0;

    while (*path != '\0') {
        SCOPED_RESLIST(rl);

        const char* path_element;
        size_t path_element_length;
        if (*path == ':') {
            path_element = ".";
            path_element_length = strlen(path_element);
            path += 1;
        } else {
            path_element = path;
            path_element_length = strcspn(path, ":");
            path += path_element_length;
        }

        char* exe = xalloc(path_element_length + 1 + file_length + 1);
        memcpy(&exe[0], path_element, path_element_length);
        exe[path_element_length] = '/';
        memcpy(&exe[path_element_length+1], file, file_length + 1);

        call_execve(exe, argv, envp);

        // Our reactions to specific errors comes from Bionic.
        // The logic here is subtle.

        switch (errno) {
            case E2BIG:
                goto done;
            case EISDIR:
            case ELOOP:
            case ENAMETOOLONG:
            case ENOENT:
                break;
            case ENOEXEC:
                try_execvpe_via_shell (exe, argv, envp);
                goto done;
            case ENOMEM:
                goto done;
            case ENOTDIR:
                break;
            case ETXTBSY:
                goto done;
            case EACCES:
                saw_eaccess = true;
                break;
            default:
                goto done;
        }
    }

    done:
    errno = errno ?: (saw_eaccess ? EACCES : ENOENT);
    die_errno("execvpe(\"%s\")", file);
}
#endif

void
xexecvp(const char* file, const char* const* argv)
{
    xexecvpe(file, argv, (const char*const*) environ);
}

struct sigtstp_cookie {
    LIST_ENTRY(sigtstp_cookie) link;
    sigtstp_callback cb;
    void* cbdata;
};

static LIST_HEAD(,sigtstp_cookie) sigtstp_handlers =
    LIST_HEAD_INITIALIZER(sigtsp_handlers);

struct sigtstp_cookie*
sigtstp_register(sigtstp_callback cb, void* cbdata)
{
    struct sigtstp_cookie* cookie = calloc(1, sizeof (*cookie));
    if (cookie == NULL)
        die_oom();

    cookie->cb = cb;
    cookie->cbdata = cbdata;
    LIST_INSERT_HEAD(&sigtstp_handlers, cookie, link);
    return cookie;
}

void
sigtstp_unregister(struct sigtstp_cookie* cookie)
{
    LIST_REMOVE(cookie, link);
    free(cookie);
}

void
job_control_signal_sigaction(int signum,
                             siginfo_t* siginfo,
                             void* context)
{
    // There can be no recovery from suspend or resume failure, so
    // just abort if something goes wrong.
    struct errhandler* saved_errh = current_errh;
    current_errh = NULL;

    struct sigtstp_cookie* cookie;
    struct sigtstp_cookie* cookie_next;

    if (signum == SIGTSTP || signum == SIGTTIN || signum == SIGTTOU) {
        LIST_FOREACH_SAFE(cookie, &sigtstp_handlers, link, cookie_next)
            cookie->cb(SIGTSTP_BEFORE_SUSPEND, cookie->cbdata);

        raise(SIGSTOP);

        // Flush the pending SIGCONT since we expect it.

        struct sigaction old_sigcont;
        struct sigaction new_sigcont = {
            .sa_handler = SIG_IGN,
        };

        VERIFY(sigaction(SIGCONT, &new_sigcont, &old_sigcont) == 0);
        sigset_t old_mask;
        sigset_t to_unblock;
        sigemptyset(&to_unblock);
        sigaddset(&to_unblock, SIGCONT);
        sigprocmask(SIG_UNBLOCK, &to_unblock, &old_mask);
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        VERIFY(sigaction(SIGCONT, &old_sigcont, NULL) == 0);

        LIST_FOREACH_SAFE(cookie, &sigtstp_handlers, link, cookie_next)
            cookie->cb(SIGTSTP_AFTER_RESUME, cookie->cbdata);

    } else {
        assert(signum == SIGCONT);
        LIST_FOREACH_SAFE(cookie, &sigtstp_handlers, link, cookie_next)
            cookie->cb(SIGTSTP_AFTER_UNEXPECTED_SIGCONT, cookie->cbdata);

    }

    current_errh = saved_errh;
}

struct sigio_cookie {
    LIST_ENTRY(sigio_cookie) link;
    sigio_callback cb;
    void* cbdata;
};

static LIST_HEAD(,sigio_cookie) sigio_handlers =
    LIST_HEAD_INITIALIZER(sigio_handlers);

struct sigio_cookie*
sigio_register(sigio_callback cb, void* cbdata)
{
    struct sigio_cookie* cookie = calloc(1, sizeof (*cookie));
    if (cookie == NULL)
        die_oom();

    cookie->cb = cb;
    cookie->cbdata = cbdata;
    LIST_INSERT_HEAD(&sigio_handlers, cookie, link);
    return cookie;
}

void
sigio_unregister(struct sigio_cookie* cookie)
{
    LIST_REMOVE(cookie, link);
    free(cookie);
}

static void
sigio_sigaction(int signum, siginfo_t* siginfo, void* context)
{
    struct sigio_cookie* cookie;
    struct sigio_cookie* cookie_next;
    LIST_FOREACH_SAFE(cookie, &sigio_handlers, link, cookie_next)
        cookie->cb(cookie->cbdata);
}

static int timeout_err;
static const char* timeout_msg;

struct set_timeout_context {
    int old_timeout_err;
    const char* old_timeout_msg;
    struct sigaction old_sigalrm;
    sigset_t old_sigmask;
    sigset_t old_signals_unblock_for_io;
    struct itimerval old_real_timer;
    struct itimerval old_virtual_timer;
    struct itimerval old_prof_timer;
    unsigned restore_real_timer : 1;
    unsigned restore_virtual_timer : 1;
    unsigned restore_prof_timer : 1;
    unsigned restore_sigmask : 1;
    unsigned restore_signals_unblock_for_io : 1;
    unsigned restore_old_sigalrm : 1;
    unsigned pending_sigalrm : 1;
};

static void
cleanup_set_timeout(void* data)
{
    struct set_timeout_context* ctx = data;

    timeout_err = ctx->old_timeout_err;
    timeout_msg = ctx->old_timeout_msg;

    if (ctx->restore_real_timer)
        setitimer(ITIMER_REAL, &ctx->old_real_timer, NULL);

    if (ctx->restore_virtual_timer)
        setitimer(ITIMER_VIRTUAL, &ctx->old_virtual_timer, NULL);

    if (ctx->restore_prof_timer)
        setitimer(ITIMER_PROF, &ctx->old_prof_timer, NULL);

    if (ctx->restore_signals_unblock_for_io)
        memcpy(&signals_unblock_for_io,
               &ctx->old_signals_unblock_for_io,
               sizeof (sigset_t));

    if (ctx->restore_old_sigalrm)
        sigaction(SIGALRM, &ctx->old_sigalrm, NULL);

    if (ctx->pending_sigalrm)
        raise(SIGALRM);

    bool restore_sigmask = ctx->restore_sigmask;
    sigset_t old_sigmask;
    if (restore_sigmask)
        memcpy(&old_sigmask, &ctx->old_sigmask, sizeof (sigset_t));

    free(ctx);
    if (restore_sigmask)
        sigprocmask(SIG_SETMASK, &old_sigmask, NULL);
}

static void
set_timeout_handle_sigalrm(int signum,
                           siginfo_t* info,
                           void* context)
{
    die(timeout_err, "%s", timeout_msg);
}

void
set_timeout(const struct itimerval* timer, int err, const char* msg)
{
    SCOPED_RESLIST(rl);

    struct cleanup* cl = cleanup_allocate();
    struct set_timeout_context* ctx = calloc(1, sizeof (*ctx));
    if (ctx == NULL) die_oom();

    ctx->old_timeout_err = timeout_err;
    ctx->old_timeout_msg = timeout_msg;

    cleanup_commit(cl, cleanup_set_timeout, ctx);

    assert(err != 0);
    assert(msg != NULL);
    timeout_err = err;
    timeout_msg = msg;

    sigset_t sigalrm_set;
    sigemptyset(&sigalrm_set);
    sigaddset(&sigalrm_set, SIGALRM);
    sigprocmask(SIG_BLOCK, &sigalrm_set, &ctx->old_sigmask);
    ctx->restore_sigmask = true;

    sigset_t all_signals;
    sigfillset(&all_signals);

    struct sigaction new_sigalrm = {
        .sa_sigaction = set_timeout_handle_sigalrm,
        .sa_mask = all_signals,
        .sa_flags = SA_SIGINFO,
    };

    sigaction(SIGALRM, &new_sigalrm, &ctx->old_sigalrm);
    ctx->restore_old_sigalrm = true;

    struct itimerval disabled_itimer = {
        .it_interval = {0, 0},
        .it_value = {0, 0 },
    };

    setitimer(ITIMER_REAL,
              &disabled_itimer,
              &ctx->old_real_timer);
    ctx->restore_real_timer = true;

    setitimer(ITIMER_VIRTUAL,
              &disabled_itimer,
              &ctx->old_virtual_timer);
    ctx->restore_virtual_timer = true;

    setitimer(ITIMER_PROF,
              &disabled_itimer,
              &ctx->old_prof_timer);
    ctx->restore_prof_timer = true;

    sigset_t pending;
    sigpending(&pending);
    bool pending_sigalrm = sigismember(&pending, SIGALRM);
    ctx->pending_sigalrm = !!pending_sigalrm;
    if (pending_sigalrm) { // Clear pending signal
        signal(SIGALRM, SIG_IGN);
        sigprocmask(SIG_UNBLOCK, &sigalrm_set, NULL);
        sigprocmask(SIG_BLOCK, &sigalrm_set, NULL);
        sigaction(SIGALRM, &new_sigalrm, NULL);
    }

    if (setitimer(ITIMER_REAL, timer, NULL) == -1)
        die_errno("setitimer");
    memcpy(&ctx->old_signals_unblock_for_io,
           &signals_unblock_for_io,
           sizeof (sigset_t));
    ctx->restore_signals_unblock_for_io = true;
    sigaddset(&signals_unblock_for_io, SIGALRM);

    reslist_xfer(rl->parent, rl);
}

static struct timeval
milliseconds_to_timeval(unsigned milliseconds)
{
    return (struct timeval) {
        .tv_sec = milliseconds / 1000,
        .tv_usec = (milliseconds % 1000) * 1000
    };
}

void
set_timeout_ms(int timeout_ms, int err, const char* msg)
{
    if (timeout_ms >= 0) {
        struct itimerval expiration = {
            .it_value = milliseconds_to_timeval(timeout_ms),
        };
        if (timeout_ms == 0)
            expiration.it_value.tv_usec = 1; // Minimum non-zero
        set_timeout(&expiration, err, msg);
    }
}

unsigned
api_level()
{
#if !defined(__ANDROID__)
    return 15;
#else
    static unsigned cached_api_level;
    unsigned api_level = cached_api_level;
    if (api_level == 0) {
        char api_level_str[PROP_VALUE_MAX];
        if (__system_property_get("ro.build.version.sdk", api_level_str) == 0)
            die(ENOENT, "cannot query system API level");
        errno = 0;
        char* endptr;
        unsigned long l_api_level = strtoul(api_level_str, &endptr, 10);
        if (errno != 0 || *endptr != '\0' || l_api_level > UINT_MAX)
            die(EINVAL, "bogus API level: \"%s\"", api_level_str);
        api_level = cached_api_level = (unsigned) l_api_level;
    }

    return api_level;
#endif
}

const char*
maybe_my_exe(const char* exename)
{
    unsigned on_valgrind = RUNNING_ON_VALGRIND;
    if (on_valgrind && !strcmp(exename, "/proc/self/exe"))
        return orig_argv0;
    return exename;
}

const char*
my_exe(void)
{
    const char* my_exe_filename = "/proc/self/exe";
#ifndef __linux__
    // A missing /proc on Linux is simply broken.  A missing /proc
    // elsewhere is just evidence of a lesser system.
    if (access(my_exe_filename, F_OK) != 0)
        my_exe_filename = orig_argv0;
#endif
    return maybe_my_exe(my_exe_filename);
}

static void
cleanup_status_pipe(void* data)
{
    int* status_pipe = data;
    if (status_pipe[0] != -1)
        xclose(status_pipe[0]);
    if (status_pipe[1] != -1)
        xclose(status_pipe[1]);
}

void
become_daemon(void (*daemon_setup)(void* setup_data),
              void* setup_data)
{
    SCOPED_RESLIST(rl);
    struct cleanup* cl = cleanup_allocate();
    uint8_t status;
    int status_pipe[2];
    if (pipe(status_pipe) == -1)
        die_errno("pipe");
    cleanup_commit(cl, cleanup_status_pipe, status_pipe);

    pid_t child = fork();

    if (child == (pid_t) -1)
        die_errno("fork");

    if (child != 0) {
        xclose(status_pipe[1]);
        status_pipe[1] = -1;
        status = 1;
        read_all(status_pipe[0], &status, sizeof (status));
        _exit(status);
    }

    xclose(status_pipe[0]);
    status_pipe[0] = -1;

    if (setsid() == (pid_t) -1)
        die_errno("setsid");

    dbg("resetting signals in daemon");
    init_signals(INIT_SIGNALS_RESET);

    VERIFY(signal(SIGHUP, SIG_IGN) != SIG_ERR);
    VERIFY(signal(SIGTTIN, SIG_IGN) != SIG_ERR);
    VERIFY(signal(SIGTTOU, SIG_IGN) != SIG_ERR);

    int devnull = xopen("/dev/null", O_RDWR, 0);

    daemon_setup(setup_data);
    xdup3nc(devnull, STDIN_FILENO, 0);
    xdup3nc(devnull, STDOUT_FILENO, 0);
    xdup3nc(devnull, STDERR_FILENO, 0);
    status = 0;
    write_all(status_pipe[1], &status, sizeof (status));
}

bool
clowny_output_line_p(const char* line)
{
    return
        string_starts_with_p(line, "Function: selinux_compare_spd_ram ,") ||
        string_starts_with_p(line, "WARNING: linker: ") ||
        string_starts_with_p(line, "[DEBUG] ");

}

void
rtrim(char* string, size_t* stringsz_inout, const char* set)
{
    size_t stringsz = stringsz_inout
        ? *stringsz_inout
        : strlen(string);
    while (stringsz > 0 && strchr(set, string[stringsz - 1]))
        stringsz--;
    string[stringsz] = '\0';
    if (stringsz_inout)
        *stringsz_inout = stringsz;
}

void
resize_buffer(struct growable_buffer* gb, size_t new_size)
{
    struct cleanup* new_cl = cleanup_allocate();
    uint8_t* new_buf = resize_alloc(gb->buf, new_size);
    if (new_buf == NULL)
        die_oom();
    cleanup_commit(new_cl, free, new_buf);
    cleanup_forget(gb->cl);
    gb->buf = new_buf;
    gb->cl = new_cl;
    gb->bufsz = new_size;
}

void
grow_buffer(struct growable_buffer* gb, size_t min)
{
    if (gb->bufsz < min)
        resize_buffer(gb, min);
}

void
grow_buffer_dwim(struct growable_buffer* gb)
{
    size_t maximum_enlargement = 1024*1024;
    size_t bufsz = gb->bufsz ?: 128;
    size_t enlargement = bufsz;
    if (enlargement > maximum_enlargement)
        enlargement = maximum_enlargement;
    if (SATADD(&bufsz, bufsz, enlargement))
        die_oom();
    resize_buffer(gb, bufsz);
}

void
growable_string_append_c(struct growable_string* gs, char c)
{
    assert(gs->strlen <= gs->gb.bufsz);
    if (gs->strlen == gs->gb.bufsz)
        grow_buffer_dwim(&gs->gb);
    assert(gs->strlen < gs->gb.bufsz);
    gs->gb.buf[gs->strlen++] = c;
}

void
growable_string_trim_trailing_whitespace(struct growable_string* gs)
{
    while (gs->strlen > 0 && strchr(" \t\r\n\v", gs->gb.buf[gs->strlen - 1]))
        gs->strlen--;
}

const char*
growable_string_c_str(struct growable_string* gs)
{
    assert(gs->strlen <= gs->gb.bufsz);
    if (gs->strlen == gs->gb.bufsz) {
        grow_buffer_dwim(&gs->gb);
    }
    assert(gs->strlen < gs->gb.bufsz);
    gs->gb.buf[gs->strlen] = '\0';
    return (const char*) &gs->gb.buf[0];
}

static void
cleanup_regfree(void* data)
{
    regfree(data);
}

regex_t*
xregcomp(const char* regex, int cflags)
{
    regex_t* reg = xcalloc(sizeof (*reg));
    struct cleanup* cl = cleanup_allocate();
    int err = regcomp(reg, regex, cflags);
    if (err != 0)
        die(EINVAL, "bad regular expression: %s", xregerror(err, reg));
    cleanup_commit(cl, cleanup_regfree, reg);
    return reg;
}


char*
xregerror(int errcode, const regex_t* preg)
{
    SCOPED_RESLIST(rl);
    struct growable_buffer gb = { 0 };
    grow_buffer_dwim(&gb);
    for (;;) {
        size_t needed = regerror(errcode, preg, (char*) gb.buf, gb.bufsz);
        if (needed <= gb.bufsz)
            break;
        resize_buffer(&gb, needed);
    }

    reslist_xfer(rl->parent, rl);
    return (char*) gb.buf;
}

