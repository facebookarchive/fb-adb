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
#include <sys/queue.h>
#include <libgen.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC O_CLOEXEC
#endif

#ifdef HAVE_KQUEUE
#include <sys/event.h>
#include <sys/time.h>
#endif

#ifdef HAVE_SIGNALFD_4
#include <sys/signalfd.h>
#endif

#include "util.h"
#include "constants.h"

struct errhandler {
    sigjmp_buf where;
    struct reslist* rl;
    struct errinfo* ei;

};

static struct reslist* current_reslist;
static struct errhandler* current_errh;
__attribute__((noreturn)) static void die_oom(void);
const char* prgname;
const char* orig_argv0;

__attribute__((unused)) static void assert_cloexec(int fd);

static void
reslist_init(struct reslist* rl, unsigned type)
{
    memset(rl, 0, sizeof (*rl));
    rl->r.type = type;
    rl->parent = current_reslist;
    LIST_INSERT_HEAD(&current_reslist->contents, &rl->r, link);
    current_reslist = rl;
}

void
reslist_init_local(struct reslist* rl_local)
{
    reslist_init(rl_local, RES_RESLIST_ONSTACK);
}

struct reslist*
reslist_push_new(void)
{
    struct reslist* rl = malloc(sizeof (*rl));
    if (rl == NULL)
        die_oom();

    reslist_init(rl, RES_RESLIST);
    return rl;
}

bool
reslist_on_chain_p(struct reslist* rl)
{
    struct reslist* crl = current_reslist;
    while (crl && crl != rl)
        crl = crl->parent;

    return crl != NULL;
}

void
reslist_pop_nodestroy(struct reslist* rl)
{
    assert(reslist_on_chain_p(rl));
    current_reslist = rl->parent;
}


static void
reslist_destroy_guts(struct reslist* rl)
{
    if (rl->parent) {
        LIST_REMOVE(&rl->r, link);
        rl->parent = NULL;
    }

    while (!LIST_EMPTY(&rl->contents)) {
        struct resource* r = LIST_FIRST(&rl->contents);
        LIST_REMOVE(r, link);
        if (r->type == RES_RESLIST || r->type == RES_RESLIST_ONSTACK) {
            struct reslist* sub_rl = (struct reslist*) r;
            sub_rl->parent = NULL;
            reslist_destroy(sub_rl);
        } else {
            struct cleanup* cl = (struct cleanup*) r;
            if (cl->fn)
                cl->fn(cl->fndata);
            free(cl);
        }
    }
}

void
reslist_destroy(struct reslist* rl)
{
    reslist_destroy_guts(rl);
    if (rl->r.type == RES_RESLIST)
        free(rl);
}

void
reslist_cleanup_local(struct reslist* rl_local)
{
    if (rl_local->parent) {
        current_reslist = rl_local->parent;
        reslist_destroy_guts(rl_local);
    }
}

struct cleanup*
cleanup_allocate(void)
{
    struct cleanup* cl = malloc(sizeof (*cl));
    if (cl == NULL)
        die_oom();

    memset(cl, 0, sizeof (*cl));
    cl->r.type = RES_CLEANUP;
    LIST_INSERT_HEAD(&current_reslist->contents, &cl->r, link);
    return cl;
}

void
cleanup_commit(struct cleanup* cl,
               cleanupfn fn,
               void* fndata)
{
    /* Regardless of where the structure was when we allocated it, put
     * it on top of the list now. */
    LIST_REMOVE(&cl->r, link);
    LIST_INSERT_HEAD(&current_reslist->contents, &cl->r, link);
    cl->fn = fn;
    cl->fndata = fndata;
}

void
cleanup_forget(struct cleanup* cl)
{
    if (cl != NULL) {
        LIST_REMOVE(&cl->r, link);
        free(cl);
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

static void
transfer_owned_resources(struct reslist* rl_to,
                         struct reslist* rl_from)
{
    LIST_HEAD(,resource) r_reversed = LIST_HEAD_INITIALIZER(&r_reversed);

    while (!LIST_EMPTY(&rl_from->contents)) {
        struct resource* r = LIST_FIRST(&rl_from->contents);
        LIST_REMOVE(r, link);
        LIST_INSERT_HEAD(&r_reversed, r, link);
    }

    while (!LIST_EMPTY(&r_reversed)) {
        struct resource* r = LIST_FIRST(&r_reversed);
        LIST_REMOVE(r, link);
        LIST_INSERT_HEAD(&rl_to->contents, r, link);
    }
}

bool
catch_error(void (*fn)(void* fndata),
            void* fndata,
            struct errinfo* ei)
{
    bool error = true;
    struct errhandler* old_errh = current_errh;
    struct errhandler errh;
    SCOPED_RESLIST(rl_cleanup);
    errh.rl = rl_cleanup;
    errh.ei = ei;
    current_errh = &errh;
    if (sigsetjmp(errh.where, 1) == 0) {
        fn(fndata);
        error = false;
        transfer_owned_resources(rl_cleanup->parent, rl_cleanup);
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

void die_oom(void)
{
    if (!current_errh)
        abort();

    current_reslist = current_errh->rl->parent;
    if (current_errh->ei) {
        current_errh->ei->err = ENOMEM;
        current_errh->ei->msg = "no memory";
    }

    siglongjmp(current_errh->where, 1);
}

void
diev(int err, const char* fmt, va_list args)
{
    if (!current_errh)
        abort();

    current_reslist = current_errh->rl->parent;
    /* die_oom will DTRT on alloc failure.  */
    struct errinfo* ei = current_errh->ei;
    if (ei) {
        ei->err = err;
        if (ei->want_msg) {
            ei->msg = xavprintf(fmt, args);
            ei->prgname = xstrdup(prgname);
        }
    }

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

__attribute__((unused))
static int
merge_flags(int fd, int flags)
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
    close(fd);
    errno = saved_errno;
}

void
assert_cloexec(int fd)
{
#ifndef NDEBUG
    int fl = fcntl(fd, F_GETFD);
    assert(fl != -1);
    assert(fl & FD_CLOEXEC);
#endif
}

#ifndef HAVE_PIPE2
int
pipe2(int fd[2], int flags)
{
    int xfd[2];
    if (pipe(xfd) < 0)
        return -1;

    for (int i = 0; i < 2; ++i)
        if (merge_flags(xfd[i], flags) < 0)
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

int
xsocket(int domain, int type, int protocol)
{
    struct cleanup* cl = cleanup_allocate();
    int s = socket(domain, type | SOCK_CLOEXEC, protocol);
    if (s < 0)
        die_errno("socket");

    assert_cloexec(s);
    cleanup_commit_close_fd(cl, s);
    return s;
}

int
xaccept(int server_socket)
{
    struct cleanup* cl = cleanup_allocate();
    int s;

    do {
#ifdef HAVE_ACCEPT4
        s = accept4(server_socket, NULL, NULL, SOCK_CLOEXEC);
#else
        s = accept(server_socket, NULL, NULL);
#endif
    } while (s == -1 && errno == EINTR);

    if (s == -1)
        die_errno("accept");

#ifndef HAVE_ACCEPT4
    merge_flags(s, O_CLOEXEC);
#endif

    assert_cloexec(s);
    cleanup_commit_close_fd(cl, s);
    return s;
}

void
xsocketpair(int domain, int type, int protocol,
            int* s1, int* s2)
{
    struct cleanup* cl[2];
    cl[0] = cleanup_allocate();
    cl[1] = cleanup_allocate();

    type |= SOCK_CLOEXEC;
    int fd[2];
    if (socketpair(domain, type, protocol, fd) < 0)
        die_errno("socketpair");

    assert_cloexec(fd[0]);
    assert_cloexec(fd[1]);

    cleanup_commit_close_fd(cl[0], fd[0]);
    cleanup_commit_close_fd(cl[1], fd[1]);
    *s1 = fd[0];
    *s2 = fd[1];
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

static void
xfopen_cleanup(void* arg)
{
    fclose((FILE*) arg);
}

FILE*
xfdopen(int fd, const char* mode)
{
    struct cleanup* cl = cleanup_allocate();
    int newfd = fcntl(fd, F_DUPFD_CLOEXEC, fd);
    if (newfd == -1)
        die_errno("F_DUPFD_CLOEXEC");
    FILE* f = fdopen(newfd, mode);
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
    struct reslist* rl = reslist_push_new();
    struct fdh* fdh = xalloc(sizeof (*fdh));
    fdh->rl = rl;
    fdh->fd = xdup(fd);
    reslist_pop_nodestroy(rl);
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

void
main1(void* arg)
{
    struct main_info* mi = arg;
    mi->ret = real_main(mi->argc, mi->argv);
}

int
main(int argc, char** argv)
{
    signal(SIGPIPE, SIG_IGN);

    struct main_info mi;
    mi.argc = argc;
    mi.argv = argv;
    struct reslist dummy_top;
    memset(&dummy_top, 0, sizeof (dummy_top));
    current_reslist = &dummy_top;
    prgname = argv[0];
    struct reslist* top_rl = reslist_push_new();
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

    reslist_destroy(top_rl);
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
    int nfd = xopen(xttyname(fd), O_RDWR | O_NOCTTY, 0);
    if (dup3(nfd, fd, O_CLOEXEC) < 0)
        die_errno("dup3");
}

size_t
read_all(int fd, void* buf, size_t sz)
{
    size_t nr_read = 0;
    int ret;
    char* pos = buf;

    while (nr_read < sz) {
        do {
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
            ret = write(fd, &pos[nr_written], sz - nr_written);
        } while (ret == -1 && errno == EINTR);

        if (ret < 0)
            die_errno("write(%d)", fd);

        nr_written += ret;
    }
}

#if !defined(HAVE_PPOLL) && defined(__linux__)
#define HAVE_PPOLL 1

# if !defined(HAVE_SIGNALFD_4)
# define SFD_CLOEXEC O_CLOEXEC
int
signalfd4(int fd, const sigset_t* mask, int flags)
{
    return syscall(__NR_signalfd4, fd, mask, flags);
}
#endif

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

static int
ppoll_emulation(struct pollfd *fds, nfds_t nfds,
                const struct timespec *timeout_ts,
                const sigset_t *sigmask)
{
    int ret = -1;
    int sfd = -1;
    sigset_t inverse_sigmask;
    struct pollfd* xfds;
    int pr;
    int poll_timeout = timespec_to_ms(timeout_ts);

    if (sigmask == NULL)
        return poll(fds, nfds, poll_timeout);

    sigemptyset(&inverse_sigmask);
    for (int i = 0; i < NSIG; ++i)
        if (!sigismember((sigset_t*) sigmask, i))
            sigaddset(&inverse_sigmask, i);

    if (nfds > INT_MAX ||
        (nfds + 1) > SIZE_MAX / sizeof (*xfds))
    {
        errno = EINVAL;
        goto out;
    }

    xfds = alloca((nfds + 1) * sizeof (*xfds));
    memcpy(&xfds[1], fds, nfds);
    memset(&xfds[0], 0, sizeof (xfds[0]));
    xfds[0].fd = sfd;
    xfds[0].events = POLLIN;

    sfd = signalfd4(-1, &inverse_sigmask, SFD_CLOEXEC);
    if (sfd == -1)
        goto out;

    pr = poll(xfds, nfds + 1, poll_timeout);
    if (pr < 1)
        goto out;

    if (xfds[0].revents & POLLIN) {
        // Got a signal.  Temporarily set sigprocmask to the one
        // specified in order to give signals a shot at delivery.
        sigset_t orig_sigmask;
        sigprocmask(SIG_SETMASK, sigmask, &orig_sigmask);
        sigprocmask(SIG_SETMASK, &orig_sigmask, NULL);
        errno = EINTR;
        goto out;
    }

    memcpy(fds, &xfds[1], nfds);
    ret = 0;

    out:

    if (sfd != -1)
        close(sfd);

    return ret;
}

int
ppoll(struct pollfd *fds, nfds_t nfds,
      const struct timespec *timeout_ts, const sigset_t *sigmask)
{
    int ret = syscall(__NR_ppoll, fds, nfds, timeout_ts, sigmask);
    if (ret == -1 && errno == ENOSYS)
        return ppoll_emulation(fds, nfds, timeout_ts, sigmask);
    return ret;
}
#endif

#if !defined(HAVE_PPOLL) && defined(HAVE_KQUEUE)
#define HAVE_PPOLL 1
int
ppoll(struct pollfd *fds, nfds_t nfds,
      const struct timespec *timeout_ts, const sigset_t *sigmask)
{
    int ret = -1;
    int kq = kqueue();
    if (kq < 0)
        goto out;

    sigset_t oldmask;
    size_t nr_events = 0;
    for (unsigned fdno = 0; fdno < nfds; ++fdno) {
        if (fds[fdno].fd == -1)
            continue;

        fds[fdno].revents = 0;

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

    struct kevent* events = alloca(sizeof (*events) * nr_events);
    memset(events, 0, sizeof (*events) * nr_events);
    int evno = 0;

    for (int sig = 1; sigmask != NULL && sig < NSIG; ++sig) {
        if (!sigismember(sigmask, sig)) {
            struct kevent* kev = &events[evno++];
            kev->ident = sig;
            kev->flags = EV_ADD;
            kev->filter = EVFILT_SIGNAL;
        }
    }

    for (unsigned fdno = 0; fdno < nfds; ++fdno) {
        if (fds[fdno].fd == -1)
            continue;

        if (fds[fdno].events & POLLIN) {
            struct kevent* kev = &events[evno++];
            kev->ident = fds[fdno].fd;
            kev->flags = EV_ADD;
            kev->filter = EVFILT_READ;
            kev->udata = &fds[fdno];
        }

        if (fds[fdno].events & POLLOUT) {
            struct kevent* kev = &events[evno++];
            kev->ident = fds[fdno].fd;
            kev->flags = EV_ADD;
            kev->filter = EVFILT_WRITE;
            kev->udata = &fds[fdno];

        }
    }

    if (sigmask)
        sigprocmask(SIG_SETMASK, sigmask, &oldmask);

    int nret = kevent(kq,
                      events,
                      nr_events,
                      events,
                      nr_events,
                      timeout_ts);

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
        struct kevent* kev = &events[evno];
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

    if (kq != -1) {
        int saved_errno;
        if (ret == -1)
            saved_errno = errno;

        close(kq);

        if (ret == -1)
            errno = saved_errno;
    }

    return ret;
}
#endif

#if !defined(HAVE_PPOLL) && defined(HAVE_PSELECT)
int
ppoll(struct pollfd *fds, nfds_t nfds,
      const struct timespec *timeout_ts, const sigset_t *sigmask)
{
}
#endif

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

    if (dup2(oldfd, newfd) < 0)
        return -1;

    if (merge_flags(newfd, flags) < 0) {
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

    if (merge_flags(newfd, flags) < 0) {
        close_saving_errno(newfd);
        return -1;
    }

    return newfd;
}
#endif

void
replace_with_dev_null(int fd)
{
    int fd_flags = fcntl(fd, F_GETFD);
    if (fd_flags < 0)
        die_errno("F_GETFD");
    int nfd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (nfd == -1)
        die_errno("open(\"/dev/null\")");
    if (dup3(nfd, fd, fd_flags & O_CLOEXEC) < 0)
        die_errno("dup3");

    close(nfd);
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
        fclose(save->stream);

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
    struct reslist* rl_buffer = reslist_push_new();
    void* buffer = xalloc(howmany);
    struct reslist* rl_urandom = reslist_push_new();
    int ufd = xopen("/dev/urandom", O_RDONLY, 0);
    size_t nr_read = read_all(ufd, buffer, howmany);
    if (nr_read < howmany)
        die(EINVAL, "too few bytes from random device");

    reslist_pop_nodestroy(rl_buffer);
    reslist_destroy(rl_urandom);
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
        sprintf(buffer + i*2, "%X%X", bytes[i] >> 4, bytes[i] & 0xF);
    }

    buffer[nr_encoded_bytes - 1] = '\0';
    return buffer;
}

char*
gen_hex_random(size_t nr_bytes)
{
    return hex_encode_bytes(generate_random_bytes(nr_bytes), nr_bytes);
}

struct addr*
make_addr_unix_filesystem(const char* filename)
{
    size_t filename_length = strlen(filename);
    size_t addrlen = offsetof(struct addr, addr_un.sun_path);
    if (SATADD(&addrlen, addrlen, filename_length + 1))
        die(EINVAL, "socket name too long");

    struct addr* a = xalloc(addrlen);
    a->size = addrlen;
    a->addr_un.sun_family = AF_UNIX;
    memcpy(a->addr_un.sun_path, filename, filename_length + 1);
    return a;
}

#ifdef __linux__
struct addr*
make_addr_unix_abstract(const void* bytes, size_t nr)
{
    size_t addrlen = offsetof(struct addr, addr_un.sun_path) + 1;
    if (SATADD(&addrlen, addrlen, nr))
        die(EINVAL, "socket name too long");

    struct addr* a = xalloc(addrlen);
    a->size = addrlen;
    a->addr_un.sun_family = AF_UNIX;
    a->addr_un.sun_path[0] = '\0';
    memcpy(a->addr_un.sun_path+1, bytes, nr);
    return a;
}
#endif

void
xconnect(int fd, const struct addr* addr)
{
    int rc;

    do {
        rc = connect(fd, &addr->addr, addr->size);
    } while (rc == -1 && errno == EINTR);

    if (rc == -1)
        die_errno("connect");
}

void
xbind(int fd, const struct addr* addr)
{
    if (bind(fd, &addr->addr, addr->size) == -1)
        die_errno("bind");
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

