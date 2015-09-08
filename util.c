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
#include <features.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <libgen.h>
#include "fs.h"
#include "valgrind.h"

#ifdef __ANDROID__
# include <sys/system_properties.h>
#endif

#if !defined(HAVE_EXECVPE)
# include <paths.h>
#endif

#ifdef HAVE_SIGNALFD_4
# include <sys/signalfd.h>
#endif

#include "util.h"
#include "constants.h"

struct errhandler {
    sigjmp_buf where;
    struct reslist* rl;
    struct errinfo* ei;
};

static struct reslist reslist_top;
static struct reslist* _reslist_current;
static struct errhandler* current_errh;
const char* prgname;
const char* orig_argv0;

sigset_t signals_unblock_for_io;
sigset_t orig_sigmask;
int signal_quit_in_progress;
bool hack_defer_quit_signals;

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

static void
reslist_insert_head(struct reslist* rl, struct resource* r)
{
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

struct unlink_cleanup {
    struct cleanup* cl;
    char* filename;
};

static void
unlink_cleanup_action(void* data)
{
    struct unlink_cleanup* ucl = data;
    (void) unlink(ucl->filename);
}

struct unlink_cleanup*
unlink_cleanup_allocate(const char* filename)
{
    struct unlink_cleanup* ucl = xcalloc(sizeof (*ucl));
    ucl->cl = cleanup_allocate();
    ucl->filename = xstrdup(filename);
    return ucl;
}

void
unlink_cleanup_commit(struct unlink_cleanup* ucl)
{
    cleanup_commit(ucl->cl, unlink_cleanup_action, ucl);
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
    errh.rl = rl;
    errh.ei = ei;
    current_errh = &errh;
    if (sigsetjmp(errh.where, 1) == 0) {
        fn(fndata);
        reslist_xfer(rl->parent, rl);
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

void
diev(int err, const char* fmt, va_list args)
{
    if (current_errh == NULL)
        abort();

    {
        // Give pending signals a chance to propagate in case we're
        // dying due to a failure ultimately caused by a
        // pending signal.
        WITH_IO_SIGNALS_ALLOWED();
    }

    if (current_errh->ei) {
        struct errinfo* ei = current_errh->ei;
        ei->err = err ?: ERR_ERRNO_WAS_ZERO;
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
quit_signal_sigaction(int signum, siginfo_t* info, void* context)
{
    signal_quit_in_progress = signum;
    if (hack_defer_quit_signals)
        return; // Caller promises to enqueue signal

    empty_reslist(&reslist_top);
    sigset_t our_signal;
    VERIFY(sigemptyset(&our_signal) == 0);
    VERIFY(sigaddset(&our_signal, signum) == 0);
    VERIFY(sigprocmask(SIG_UNBLOCK, &our_signal, NULL) == 0);
    // SA_RESETHAND ensures that we run the default handler here
    raise(signum);
    abort();
}

static void job_control_signal_sigaction(int, siginfo_t*,void*);

static void
handle_sigchld(int signo)
{
    // Noop: we just need any handler
}

void
main1(void* arg)
{
    struct main_info* mi = arg;

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

    int job_control_signals[] = { SIGCONT, SIGTSTP };

    sigset_t to_block_mask;
    sigemptyset(&to_block_mask);
    for (int i = 0; i < ARRAYSIZE(quit_signals); ++i)
        sigaddset(&to_block_mask, quit_signals[i]);
    for (int i = 0; i < ARRAYSIZE(job_control_signals); ++i)
        sigaddset(&to_block_mask, job_control_signals[i]);

    // See comment in child.c.
    VERIFY(signal(SIGCHLD, handle_sigchld) != SIG_ERR);
    sigaddset(&to_block_mask, SIGCHLD);

    VERIFY(sigprocmask(SIG_BLOCK, &to_block_mask, &orig_sigmask) == 0);

    sigset_t all_signals_mask;
    VERIFY(sigfillset(&all_signals_mask) == 0);

    for (int i = 0; i < ARRAYSIZE(quit_signals); ++i) {
        struct sigaction sa;
        memset(&sa, 0, sizeof (sa));
        sa.sa_sigaction = quit_signal_sigaction;
        sa.sa_mask = all_signals_mask;
        sa.sa_flags = SA_RESETHAND | SA_SIGINFO;
        VERIFY(sigaction(quit_signals[i], &sa, NULL) == 0);
        sigaddset(&signals_unblock_for_io, quit_signals[i]);
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

    _fs_on_init();
    mi->ret = real_main(mi->argc, mi->argv);
}

int
main(int argc, char** argv)
{
    VERIFY(signal(SIGPIPE, SIG_IGN) != SIG_ERR);

    sigemptyset(&signals_unblock_for_io);

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
    struct errinfo ei = { .want_msg = true };
    if (catch_error(main1, &mi, &ei)) {
        mi.ret = 1;
        dbg("ERROR: %s: %s", ei.prgname, ei.msg);
        fprintf(stderr, "%s: %s\n", ei.prgname, ei.msg);
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
        sprintf(buffer + i*2, "%02x%02x",
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



#ifdef HAVE_EXECVPE
void
xexecvpe(const char* file,
         const char* const* argv,
         const char* const* envp)
{
    execvpe(file,
            (char* const*) argv,
            (char* const*) envp);
    die_errno("execvpe(\"%s\")", file);
}
#else
static void
call_execve(const char* file,
            const char* const* argv,
            const char* const* envp)
{
    (void) execve(file, (char* const*) argv, (char* const*) envp);
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

    if (signum == SIGTSTP) {
        LIST_FOREACH(cookie, &sigtstp_handlers, link)
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

        LIST_FOREACH(cookie, &sigtstp_handlers, link)
            cookie->cb(SIGTSTP_AFTER_RESUME, cookie->cbdata);

    } else {
        assert(signum == SIGCONT);
        LIST_FOREACH(cookie, &sigtstp_handlers, link)
            cookie->cb(SIGTSTP_AFTER_UNEXPECTED_SIGCONT, cookie->cbdata);

    }

    current_errh = saved_errh;
}

struct set_timeout_context {
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
    die(EAGAIN, "timeout");
}

void
set_timeout(const struct itimerval* timer)
{
    SCOPED_RESLIST(rl);

    struct cleanup* cl = cleanup_allocate();
    struct set_timeout_context* ctx = calloc(1, sizeof (*ctx));
    if (ctx == NULL) die_oom();
    cleanup_commit(cl, cleanup_set_timeout, ctx);

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

    setitimer(ITIMER_REAL, timer, NULL);
    memcpy(&ctx->old_signals_unblock_for_io,
           &signals_unblock_for_io,
           sizeof (sigset_t));
    ctx->restore_signals_unblock_for_io = true;
    sigaddset(&signals_unblock_for_io, SIGALRM);

    reslist_xfer(rl->parent, rl);
}

#ifdef __ANDROID__
unsigned
api_level()
{
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
}
#endif

const char*
my_exe(void)
{
    unsigned on_valgrind = RUNNING_ON_VALGRIND;
    return on_valgrind ? orig_argv0 : "/proc/self/exe";
}
