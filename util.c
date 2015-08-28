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
#include <signal.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <libgen.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/stat.h>

#if !defined(HAVE_EXECVPE)
#include <paths.h>
#endif

#ifdef HAVE_SIGNALFD_4
#include <sys/signalfd.h>
#endif

#include "util.h"
#include "constants.h"

#if XPPOLL == XPPOLL_KQUEUE
#include <sys/event.h>
#include <sys/time.h>
static int ppoll_kq = -1;
#endif

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
               void* fndata)
{
    // Regardless of where the structure was when we allocated it, put
    // it on top of the stack now.
    assert(cl->fn == NULL);
    cl->fn = fn;
    cl->fndata = fndata;
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

static void
fd_cleanup(void* arg)
{
    xclose((intptr_t) arg);
}

void
cleanup_commit_close_fd(struct cleanup* cl, int fd)
{
    cleanup_commit(cl, fd_cleanup, (void*) (intptr_t) (fd));
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
        // Give pending signals a chance to propagate
        WITH_IO_SIGNALS_ALLOWED();
    }

    if (current_errh->ei) {
        struct errinfo* ei = current_errh->ei;
        ei->err = err;
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

int
xopen(const char* pathname, int flags, mode_t mode)
{
    struct cleanup* cl = cleanup_allocate();
    int fd = open(pathname, flags | O_CLOEXEC, mode);
    if (fd == -1)
        die_errno("open(\"%s\")", pathname);

    assert_cloexec(fd);
    cleanup_commit_close_fd(cl, fd);
    return fd;
}

void
xclose(int fd)
{
    // If close fails with EIO or EINTR error, it still closes the FD.
    // Only EBADF indicates a failure to close something.
    if (close(fd) == -1 && errno == EBADF)
        die_errno("close");
}

int
merge_O_CLOEXEC_into_fd_flags(int fd, int flags)
{
    assert(flags == 0 || flags == O_CLOEXEC);
    if (flags != 0) {
        int fl = fcntl(fd, F_GETFD);
        if (fl < 0 || fcntl(fd, F_SETFD, fl | FD_CLOEXEC) < 0)
            return -1;

        assert_cloexec(fd);
    }

    return 0;
}

__attribute__((unused))
static void
close_saving_errno(int fd)
{
    int saved_errno = errno;
    xclose(fd);
    errno = saved_errno;
}

#ifndef NDEBUG
void
assert_cloexec(int fd)
{
    int fl = fcntl(fd, F_GETFD);
    assert(fl != -1);
    assert(fl & FD_CLOEXEC);
}
#endif

#ifndef HAVE_PIPE2
int
pipe2(int fd[2], int flags)
{
    int xfd[2];
    if (pipe(xfd) < 0)
        return -1;

    for (int i = 0; i < 2; ++i)
        if (merge_O_CLOEXEC_into_fd_flags(xfd[i], flags) < 0)
            goto fail;

    fd[0] = xfd[0];
    fd[1] = xfd[1];
    return 0;

    fail:
    close_saving_errno(xfd[0]);
    close_saving_errno(xfd[1]);
    return -1;
}
#endif

void
xpipe(int* read_end, int* write_end)
{
    struct cleanup* cl[2];
    cl[0] = cleanup_allocate();
    cl[1] = cleanup_allocate();

    int fd[2];
    if (pipe2(fd, O_CLOEXEC) < 0)
        die_errno("pipe2");

    assert_cloexec(fd[0]);
    assert_cloexec(fd[1]);

    cleanup_commit_close_fd(cl[0], fd[0]);
    cleanup_commit_close_fd(cl[1], fd[1]);
    *read_end = fd[0];
    *write_end = fd[1];
}

#if !defined(F_DUPFD_CLOEXEC) && defined(__linux__)
#define F_DUPFD_CLOEXEC 1030
#endif

int
xdup(int fd)
{
    struct cleanup* cl = cleanup_allocate();
    int newfd = fcntl(fd, F_DUPFD_CLOEXEC, fd);
    if (newfd == -1)
        die_errno("F_DUPFD_CLOEXEC");

    assert_cloexec(newfd);
    cleanup_commit_close_fd(cl, newfd);
    return newfd;
}

int
xdup3nc(int oldfd, int newfd, int flags)
{
    int rc;

    do {
        rc = dup3(oldfd, newfd, flags);
    } while (rc < 0 && errno == EINTR);

    if (rc < 0)
        die_errno("dup3");

    return rc;
}

#ifdef HAVE_FOPENCOOKIE
typedef ssize_t custom_stream_ssize_t;
typedef size_t custom_stream_size_t;
#else
typedef int custom_stream_ssize_t;
typedef int custom_stream_size_t;
#endif

static void
xfopen_cleanup(void* arg)
{
    fclose((FILE*) arg);
}

static int
xfdopen_fd(void* cookie)
{
    return (int) (intptr_t) cookie;
}

static custom_stream_ssize_t
xfdopen_read(void* cookie, char* buf, custom_stream_size_t size)
{
    assert(!hack_defer_quit_signals);
    ssize_t ret;

    hack_defer_quit_signals = true;
    do {
        WITH_IO_SIGNALS_ALLOWED();
        ret = read(xfdopen_fd(cookie), buf, size);
    } while (ret == -1 && errno == EINTR && !signal_quit_in_progress);
    hack_defer_quit_signals = false;

    if (ret == -1 && errno == EINTR && signal_quit_in_progress) {
        raise(signal_quit_in_progress); // Queue signal
        signal_quit_in_progress = 0;
        errno = EIO; // Prevent retry
    }

    return ret;
}

static custom_stream_ssize_t
xfdopen_write(void* cookie, const char* buf, custom_stream_size_t size)
{
    assert(!hack_defer_quit_signals);
    ssize_t ret;

    hack_defer_quit_signals = true;
    do {
        WITH_IO_SIGNALS_ALLOWED();
        ret = write(xfdopen_fd(cookie), buf, size);
    } while (ret == -1 && errno == EINTR && !signal_quit_in_progress);
    hack_defer_quit_signals = false;

    if (ret == -1 && errno == EINTR && signal_quit_in_progress) {
        raise(signal_quit_in_progress); // Queue signal
        signal_quit_in_progress = 0;
        errno = EIO; // Prevent retry
    }

    return ret;
}

static int
xfdopen_close(void* cookie)
{
    xclose(xfdopen_fd(cookie));
    return 0;
}

FILE*
xfdopen(int fd, const char* mode)
{
    struct cleanup* cl = cleanup_allocate();
    int newfd = fcntl(fd, F_DUPFD_CLOEXEC, fd);
    if (newfd == -1)
        die_errno("F_DUPFD_CLOEXEC");

    FILE* f = NULL;

#if defined(HAVE_FOPENCOOKIE)
    cookie_io_functions_t funcs = {
        .read = xfdopen_read,
        .write = xfdopen_write,
        .seek = NULL,
        .close = xfdopen_close,
    };

    f = fopencookie((void*) (intptr_t) newfd, mode, funcs);
#elif defined(HAVE_FUNOPEN)
    f = funopen((void*) (intptr_t) newfd,
                xfdopen_read,
                xfdopen_write,
                NULL,
                xfdopen_close);
#else
# error This platform has no custom stdio stream support
#endif

    if (f == NULL) {
        close_saving_errno(newfd);
        die_errno("fdopen");
    }
    cleanup_commit(cl, xfopen_cleanup, f);
    return f;
}

// Like xdup, but return a structure that allows the fd to be
// individually closed.
struct fdh*
fdh_dup(int fd)
{
    struct reslist* rl = reslist_create();
    WITH_CURRENT_RESLIST(rl);

    struct fdh* fdh = xalloc(sizeof (*fdh));
    fdh->rl = rl;
    fdh->fd = xdup(fd);
    return fdh;
}

void
fdh_destroy(struct fdh* fdh)
{
    reslist_destroy(fdh->rl);
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

    static const int quit_signals[] = {
        SIGHUP, SIGINT, SIGQUIT, SIGTERM
    };

    sigset_t to_block_mask;
    sigemptyset(&to_block_mask);;
    for (int i = 0; i < ARRAYSIZE(quit_signals); ++i)
        sigaddset(&to_block_mask, quit_signals[i]);

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

#if XPPOLL == XPPOLL_KQUEUE
    ppoll_kq = kqueue(); // Not inherited across fork
    if (ppoll_kq < 0)
        die_errno("kqueue");
#endif

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
    prgname = strdup(basename(xstrdup(argv[0])));
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

enum blocking_mode
fd_set_blocking_mode(int fd, enum blocking_mode mode)
{
    int flags = fcntl(fd, F_GETFL);
    enum blocking_mode old_mode;
    if (flags < 0)
        die_errno("fcntl(%d, F_GETFL)", fd);

    old_mode = (flags & O_NONBLOCK) ? non_blocking : blocking;
    if (mode == non_blocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }

    if (fcntl(fd, F_SETFL, flags) < 0)
        die_errno("fcntl(%d, F_SETFL, %x)", fd, flags);

    return old_mode;
}

static const char*
xttyname(int fd)
{
#ifndef __ANDROID__
    return ttyname(fd);
#else
    char buf[512];
    ssize_t nr = readlink(xaprintf("/proc/self/fd/%d", fd),
                          buf, sizeof (buf) - 1);
    if (nr < 0)
        die_errno("readlink");

    buf[nr] = '\0';
    return xstrdup(buf);
#endif
}

void
hack_reopen_tty(int fd)
{
    // We sometimes need O_NONBLOCK on our input and output streams,
    // but O_NONBLOCK applies to the entire file object.  If the file
    // object happens to be a tty we've inherited, everything that
    // uses that tty will start getting EAGAIN and all hell will break
    // loose.  Here, we reopen the tty so we can get a fresh file
    // object and control the blocking mode separately.
    SCOPED_RESLIST(rl_hack);
    xdup3nc(xopen(xttyname(fd), O_RDWR | O_NOCTTY, 0), fd, O_CLOEXEC);
}

size_t
read_all(int fd, void* buf, size_t sz)
{
    size_t nr_read = 0;
    int ret;
    char* pos = buf;

    while (nr_read < sz) {
        do {
            WITH_IO_SIGNALS_ALLOWED();
            ret = read(fd, &pos[nr_read], sz - nr_read);
        } while (ret == -1 && errno == EINTR);

        if (ret < 0)
            die_errno("read(%d)", fd);

        if (ret < 1)
            break;

        nr_read += ret;
    }

    return nr_read;
}

void
write_all(int fd, const void* buf, size_t sz)
{
    size_t nr_written = 0;
    int ret;
    const char* pos = buf;

    while (nr_written < sz) {
        do {
            WITH_IO_SIGNALS_ALLOWED();
            ret = write(fd, &pos[nr_written], sz - nr_written);
        } while (ret == -1 && errno == EINTR);

        if (ret < 0)
            die_errno("write(%d)", fd);

        nr_written += ret;
    }
}

__attribute__((unused))
static int
timespec_to_ms(const struct timespec* ts)
{
    static const int ns_per_ms = 1000000;

    if (ts == NULL)
        return -1;

    if (ts->tv_sec > INT_MAX / 1000)
        return INT_MAX;

    return ts->tv_sec * 1000 + ts->tv_nsec / ns_per_ms;
}

#if XPPOLL == XPPOLL_LINUX_SYSCALL
int
xppoll(struct pollfd *fds, nfds_t nfds,
       const struct timespec *timeout_ts, const sigset_t *sigmask)
{
    struct timespec timeout_local;
    if (timeout_ts) {
        memcpy(&timeout_local, timeout_ts, sizeof (*timeout_ts));
        timeout_ts = &timeout_local;
    }

    return syscall(__NR_ppoll, fds, nfds, timeout_ts, sigmask, _NSIG/8);
}
#elif XPPOLL == XPPOLL_KQUEUE
int
xppoll(struct pollfd *fds, nfds_t nfds,
       const struct timespec *timeout_ts, const sigset_t *sigmask)
{
    int ret = -1;
    int kq = ppoll_kq;

    assert(kq != -1); // Should have initialized in main()

    sigset_t oldmask;
    size_t nr_events = 0;
    struct kevent* events = NULL;
    struct kevent* revents = NULL;
    int nret;
    int nr_installed_events = 0;
    int saved_errno;
    struct stat si;

    for (unsigned fdno = 0; fdno < nfds; ++fdno)
        fds[fdno].revents = 0;

    for (unsigned fdno = 0; fdno < nfds; ++fdno) {
        if (fds[fdno].fd == -1)
            continue;

        if ((fds[fdno].events & (POLLIN|POLLOUT)) == 0)
            continue;

        if (fstat(fds[fdno].fd, &si) == -1)
            return -1;

        if ((si.st_mode & S_IFMT) == S_IFREG) {
            // kqueue has bizarre and rarely useful semantics for
            // regular files, so assume that disk files are always
            // capable of IO.
            fds[fdno].revents = fds[fdno].events & (POLLIN|POLLOUT);
            return 1;
        }

        if (fds[fdno].events & POLLIN)
            nr_events++;

        if (fds[fdno].events & POLLOUT)
            nr_events++;
    }

    for (int sig = 1; sigmask != NULL && sig < NSIG; ++sig)
        if (!sigismember(sigmask, sig))
            nr_events += 1;

    if (nr_events > INT_MAX ||
        nr_events > SIZE_MAX / sizeof (struct kevent))
    {
        errno = EINVAL;
        goto out;
    }

    events = alloca(sizeof (*events) * nr_events);
    memset(events, 0, sizeof (*events) * nr_events);
    revents = alloca(sizeof (*revents) * nr_events);

    int evno = 0;

    for (int sig = 1; sigmask != NULL && sig < NSIG; ++sig) {
        if (!sigismember(sigmask, sig)) {
            struct kevent* kev = &events[evno++];
            kev->ident = sig;
            kev->flags = EV_ADD | EV_RECEIPT;
            kev->filter = EVFILT_SIGNAL;
        }
    }

    for (unsigned fdno = 0; fdno < nfds; ++fdno) {
        if (fds[fdno].fd == -1)
            continue;

        if (fds[fdno].events & POLLIN) {
            struct kevent* kev = &events[evno++];
            kev->ident = fds[fdno].fd;
            kev->flags = EV_ADD | EV_RECEIPT;
            kev->filter = EVFILT_READ;
            kev->udata = &fds[fdno];
        }

        if (fds[fdno].events & POLLOUT) {
            struct kevent* kev = &events[evno++];
            kev->ident = fds[fdno].fd;
            kev->flags = EV_ADD | EV_RECEIPT;
            kev->filter = EVFILT_WRITE;
            kev->udata = &fds[fdno];

        }
    }

    // Register event filters, but don't receive any events yet.

    nret = kevent(kq, events, nr_events, revents, nr_events, 0);
    if (nret < 0) {
        if (errno != EINTR)
            dbg("kevent itself failed: %d", nret);
        goto out;
    }

    int nr_invalid_fds = 0;
    ret = 0;
    for (evno = 0; evno < nret; ++evno) {
        if ((revents[evno].flags & EV_ERROR) == 0) {
            dbg("did not get EV_ERROR from revents as expected: "
                "flags: 0x%08x", (unsigned) revents[evno].flags);
            abort();
        }

        if (revents[evno].data == 0) {
            struct kevent* undo_event = &events[nr_installed_events++];
            memset(undo_event, 0, sizeof (*undo_event));
            undo_event->ident = revents[evno].ident;
            undo_event->filter = revents[evno].filter;
            undo_event->flags = EV_DELETE | EV_RECEIPT;
        } else if (revents[evno].udata != NULL) {
            struct pollfd* fd = revents[evno].udata;
            fd->revents = POLLNVAL;
            ++nr_invalid_fds;
        } else {
            errno = revents[evno].data;
            ret = -1;
        }
    }

    if (ret != 0)
        goto out;

    ret = -1;

    if (nr_invalid_fds > 0) {
        ret = nr_invalid_fds;
        goto out;
    }

    // EVFILT_SIGNAL doesn't trigger for signals that were already
    // pending before kqueue(2), so we need to explicitly check
    // whether any were pending.  We allowed these signals to be
    // delivered with SIG_SETMASK, so the EINTR return just reflects
    // the signal delivery that already happened.

    if (sigmask) {
        sigset_t pending;
        sigpending(&pending);
        sigprocmask(SIG_SETMASK, sigmask, &oldmask);
        for (int sig = 1; sig < NSIG; ++sig) {
            if (sigismember(&pending, sig) && !sigismember(sigmask, sig)) {
                sigprocmask(SIG_SETMASK, &oldmask, NULL);
                errno = EINTR;
                goto out;
            }
        }
    }

    nret = kevent(kq, NULL, 0, revents, nr_events, timeout_ts);
    if (sigmask)
        sigprocmask(SIG_SETMASK, &oldmask, NULL);

    if (nret < 0) {
        if (errno != EINTR)
            dbg("kevent itself failed: %d", nret);
        goto out;
    }

    int nr_happened = 0;
    bool sig_happened = false;

    for (evno = 0; evno < nret; ++evno) {
        struct kevent* kev = &revents[evno];
        if (kev->filter == EVFILT_READ ||
            kev->filter == EVFILT_WRITE)
        {
            struct pollfd* p = kev->udata;
            assert(p != NULL && p->fd == kev->ident);
            if (p->revents == 0)
                nr_happened += 1;

            p->revents |= (kev->filter == EVFILT_READ ? POLLIN : POLLOUT);
        }

        if (kev->filter == EVFILT_SIGNAL) {
            assert(kev->data != 0);
            dbg("got signal %d", (int) kev->data);
            sig_happened = true;
        }
    }

    dbg("sig_happened:%d nr_happened:%d", (int)sig_happened, nr_happened);

    if (sig_happened && !nr_happened) {
        errno = EINTR;
        goto out;
    }

    ret = nr_happened;

    out:

    saved_errno = errno;
    do {
        nret = kevent(kq, events, nr_installed_events,
                      revents, nr_events, NULL);
    } while (nret == -1 && errno == EINTR);

    if (nret < 0) {
        dbg("deleting filters failed with errno %d", errno);
        abort(); // Deleting filters should never fail
    }

    errno = saved_errno;

    return ret;
}
#elif XPPOLL == XPPOLL_SYSTEM
int
xppoll(struct pollfd *fds, nfds_t nfds,
       const struct timespec *timeout_ts, const sigset_t *sigmask)
{
    return ppoll(fds, nfds, timeout_ts, sigmask);
}
#elif XPPOLL == XPPOLL_STUPID_WRAPPER
int
xppoll(struct pollfd *fds, nfds_t nfds,
       const struct timespec *timeout_ts, const sigset_t *sigmask)
{
    int ret;
    sigset_t saved_sigmask;

    sigprocmask(SIG_SETMASK, sigmask, &saved_sigmask);
    ret = poll(fds, nfds, timespec_to_ms(timeout_ts));
    sigprocmask(SIG_SETMASK, &saved_sigmask, NULL);
    return ret;
}
#else
# error Y U no decent signal handling
#endif /* xppoll implementation */

#ifndef HAVE_DUP3
int
dup3(int oldfd, int newfd, int flags)
{
#ifdef __linux__
    return syscall(__NR_dup3, oldfd, newfd, flags);
#else
    if (oldfd == newfd) {
        errno = EINVAL;
        return -1;
    }

    int rc = dup2(oldfd, newfd);
    if (rc < 0)
        return -1;

    if (merge_O_CLOEXEC_into_fd_flags(newfd, flags) < 0) {
        close_saving_errno(newfd);
        return -1;
    }

    return newfd;
#endif
}
#endif

#ifndef HAVE_MKOSTEMP
int
mkostemp(char *template, int flags)
{
    int newfd = mkstemp(template);
    if (newfd == -1)
        return -1;

    if (merge_O_CLOEXEC_into_fd_flags(newfd, flags) < 0) {
        close_saving_errno(newfd);
        return -1;
    }

    return newfd;
}
#endif

void
replace_with_dev_null(int fd)
{
    SCOPED_RESLIST(rl);
    int fd_flags = fcntl(fd, F_GETFD);
    if (fd_flags < 0)
        die_errno("F_GETFD");
    int nfd = xopen("/dev/null", O_RDWR | O_CLOEXEC, 0);
    xdup3nc(nfd, fd, fd_flags & O_CLOEXEC);
}

struct xnamed_tempfile_save {
    char* name;
    int fd;
    FILE* stream;
};

static void
xnamed_tempfile_cleanup(void* arg)
{
    struct xnamed_tempfile_save* save = arg;

    if (save->fd != -1)
        xclose(save->fd);

    if (save->stream)
        (void) fclose(save->stream);

    if (save->name)
        (void) unlink(save->name);
}

FILE*
xnamed_tempfile(const char** out_name)
{
    struct xnamed_tempfile_save* save = xcalloc(sizeof (*save));
    char* name = xaprintf("%s/fb-adb-XXXXXX", DEFAULT_TEMP_DIR);
    struct cleanup* cl = cleanup_allocate();
    cleanup_commit(cl, xnamed_tempfile_cleanup, save);
    save->fd = mkostemp(name, O_CLOEXEC);
    if (save->fd == -1)
        die_errno("mkostemp");

    save->name = name;
    save->stream = fdopen(save->fd, "r+");
    if (save->stream == NULL)
        die_errno("fdopen");

    save->fd = -1; // stream owns it now
    *out_name = name;
    return save->stream;
}

void
allow_inherit(int fd)
{
    int fl = fcntl(fd, F_GETFD);
    if (fl < 0 || fcntl(fd, F_SETFD, fl &~ FD_CLOEXEC) < 0)
        die_errno("fcntl");
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
        sprintf(buffer + i*2, "%x%x", bytes[i] >> 4, bytes[i] & 0xF);
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

int
default_getopt(char c, const char** argv, const char* usage)
{
    switch (c) {
        case ':':
            if (optopt == '\0') {
                die(EINVAL, "missing argument for %s", argv[optind-1]);
            } else {
                die(EINVAL, "missing argument for -%c", optopt);
            }
        case '?':
            if (optopt == '?') {
                // Fall through to help
            } else if (optopt == '\0') {
                die(EINVAL, "invalid option %s", argv[optind-1]);
            } else {
                die(EINVAL, "invalid option -%c", (int) optopt);
            }
        case 'h':
            fputs(usage, stdout);
            exit(0);
        default:
            abort();

    }
}
