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
#include <sys/syscall.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <libgen.h>
#include <string.h>
#include <limits.h>
#include "fs.h"
#include "constants.h"
#include "sha2.h"

#if XPPOLL == XPPOLL_KQUEUE
# include <sys/event.h>
# include <sys/time.h>
static int ppoll_kq = -1;
#endif

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

int
try_xopen(const char* pathname, int flags, mode_t mode)
{
    struct cleanup* cl = cleanup_allocate();
    int fd = open(pathname, flags | O_CLOEXEC, mode);
    if (fd == -1) {
        cleanup_forget(cl);
        return -1;
    }

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
        die_errno("F_DUPFD_CLOEXEC(%d)", fd);

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
        die_errno("dup3(%d,%d,0x%x)", oldfd, newfd, (unsigned) flags);

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
    return xreadlink(xaprintf("/proc/self/fd/%d", fd));
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

int
xpoll(struct pollfd* fds, nfds_t nfds, int timeout)
{
    WITH_IO_SIGNALS_ALLOWED();
    int pollret;
    do {
        pollret = poll(fds, nfds, timeout);
    } while (pollret == -1 && errno == EINTR);

    return pollret;
}

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
replace_stdin_stdout_with_dev_null(void)
{
    SCOPED_RESLIST(rl);
    int devnull = xopen("/dev/null", O_RDWR, 0);
    xdup3nc(devnull, STDIN_FILENO, 0);
    xdup3nc(devnull, STDOUT_FILENO, 0);
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

char*
xreadlink(const char* path)
{
    struct cleanup* cl = NULL;
    char* buf = NULL;
    size_t bufsz = 64;
    ssize_t rc;

    do {
        bufsz *= 2;
        if (bufsz > (size_t) SSIZE_MAX)
            die(EINVAL, "readlink path too long");

        if (cl) {
            free(buf);
            cleanup_forget(cl);
        }

        cl = cleanup_allocate();
        buf = malloc(bufsz+1);
        if (buf == NULL)
            die_oom();
        cleanup_commit(cl, free, buf);
        rc = readlink(path, buf, bufsz);
    } while (rc > 0 && rc == bufsz);

    if (rc < 0)
        die(errno, "%s", strerror(errno));

    buf[rc] = '\0';
    return buf;
}

char*
xdirname(const char* path)
{
    SCOPED_RESLIST(rl);
    char* xpath = xstrdup(path);
    char* ret = dirname(xpath);
    WITH_CURRENT_RESLIST(rl->parent);
    return xstrdup(ret);
}

char*
xbasename(const char* path)
{
    SCOPED_RESLIST(rl);
    char* xpath = xstrdup(path);
    char* ret = basename(xpath);
    WITH_CURRENT_RESLIST(rl->parent);
    return xstrdup(ret);
}

#ifdef HAVE_XFALLOCATE
# undef HAVE_FUNOPEN
#endif

#if !defined(HAVE_FALLOCATE) &&                 \
    defined(__linux__) &&                       \
    defined(__NR_fallocate) && (                \
        defined(__ARM_EABI__) ||                \
        defined(__i386__))
__attribute__((unused))
static int
xfallocate(int fd, int mode, uint64_t offset, uint64_t length)
{
# ifdef __ARM_EABI__
    return syscall(__NR_fallocate, fd, mode,
                   (uint32_t)(offset >> 32),
                   (uint32_t)(offset >> 0),
                   (uint32_t)(length >> 32),
                   (uint32_t)(length >> 0));
# else
    return syscall(__NR_fallocate, fd, mode, offset, length);
# endif
}
# define HAVE_XFALLOCATE 1
#endif

#ifndef OFF_T_MAX
# if SIZEOF_OFF_T==8
#  define OFF_T_MAX INT64_MAX
# elif SIZEOF_OFF_T==4
#  define OFF_T_MAX INT32_MAX
# else
#  error "bizarre system"
# endif
#endif

bool
fallocate_if_supported(int fd, uint64_t size)
{
    int ret;
    uint64_t max_size;

#if defined(HAVE_XFALLOCATE)
    max_size = INT64_MAX;
#else
    max_size = OFF_T_MAX;
#endif

    if (size > max_size)
        die(EINVAL, "file size too large");

#if HAVE_FALLOCATE && SIZEOF_OFF_T==4
    ret = xfallocate(fd, 0, 0, size);
#elif defined(HAVE_POSIX_FALLOCATE) && !defined(__GLIBC__)
    // Use the Linux system call directly instead of posix_fallocate
    // because glibc exceeds even its high standard of badness and
    // tries to emulate posix_fallocate using goddamn pwrite on
    // filesystem where rela fallocate isn't available.
    // This emulation is unforgivable: it causes silent data loss!
    //
    // tl;dr: we can't trust posix_fallocate on glibc systems.  How
    // the hell do open source systems manage to boot?
    ret = posix_fallocate(fd, 0, size);
#elif defined(HAVE_FALLOCATE)
    ret = fallocate(fd, 0, 0, size);
#elif defined(HAVE_XFALLOCATE)
    ret = xfallocate(fd, 0, 0, size);
#else
    ret = -1;
    errno = ENOSYS;
#endif

    if (ret == -1) {
        if (errno != ENOSYS && errno != EOPNOTSUPP)
            die_errno("fallocate");
        return false;
    }

    return true;
}

void
xfsync(int fd)
{
    if (fsync(fd) == -1)
        die_errno("fsync");
}

void
xftruncate(int fd, uint64_t size)
{
    size_t max_size;

#if SIZEOF_OFF_T==4 && defined(HAVE_FALLOCATE64)
    max_size = INT64_MAX;
#else
    max_size = OFF_T_MAX;
#endif

    if (size > max_size)
        die(EINVAL, "file size too large");

    int ret;

#if SIZEOF_OFF_T==4 && defined(HAVE_FALLOCATE64)
    ret = ftruncate64(fd, (off64_t) size);
#else
    ret = ftruncate(fd, (off_t) size);
#endif

    if (ret == -1)
        die_errno("ftruncate");
}

void
xrename(const char* old, const char* new)
{
    if (rename(old, new) == -1)
        die_errno("rename");
}

#if defined(__linux__) && !defined(POSIX_FADV_SEQUENTIAL)
#define POSIX_FADV_SEQUENTIAL 2
#endif

void
hint_sequential_access(int fd)
{
    int advice = POSIX_FADV_SEQUENTIAL;
#if defined(HAVE_POSIX_FADVISE)
    (void) posix_fadvise(fd, 0, 0, advice);
#elif defined(__linux__) && defined(__NR_arm_fadvise64_64)
    (void) syscall(__NR_arm_fadvise64_64, fd, advice, 0, 0, 0, 0);
#elif defined(__linux__) && defined(__NR_fadvise64)
    (void) syscall(__NR_fadvise64, fd, 0, 0, 0, 0, advice);
#endif
}

void
xputc(char c, FILE* out)
{
    if (putc(c, out) == EOF)
        die_errno("putc");
}

void
xputs(const char* s, FILE* out)
{
    if (fputs(s, out) == EOF)
        die_errno("fputs");
}

void
xflush(FILE* out)
{
    if (fflush(out) == -1)
        die_errno("fflush");
}

void
_fs_on_init(void)
{
#if XPPOLL == XPPOLL_KQUEUE
    ppoll_kq = kqueue(); // Not inherited across fork
    if (ppoll_kq < 0)
        die_errno("kqueue");
#endif
}

const char*
system_tempdir(void)
{
#ifdef __ANDROID__
    return DEFAULT_TEMP_DIR;
#else
    return (const char*) first_non_null(
        getenv("TEMP"),
        getenv("TMP"),
        getenv("TMPDIR"),
        DEFAULT_TEMP_DIR);
#endif
}

struct sha256_hash
sha256_fd(int fd)
{
    struct sha256_hash sh;

    SCOPED_RESLIST(rl);

    _Static_assert(
        sizeof (sh.digest) == SHA256_DIGEST_LENGTH,
        "hash size mismatch");

    size_t bufsz = 32768;
    uint8_t* buf = xalloc(bufsz);
    size_t nr_read;
    SHA256_CTX sha256;

    SHA256_Init(&sha256);
    while ((nr_read = read_all(fd, buf, bufsz)) > 0) {
        SHA256_Update(&sha256, buf, nr_read);
    }
    SHA256_Final(sh.digest, &sha256);
    return sh;
}

void
xrewindfd(int fd)
{
    if (lseek(fd, 0, SEEK_SET) == (off_t) -1)
        die_errno("lseek");
}

#ifdef HAVE_REALPATH
const char*
xrealpath(const char* path)
{
    struct cleanup* cl = cleanup_allocate();
    char* resolved_path = realpath(path, NULL);
    if (resolved_path == NULL)
        die_errno("realpath(\"%s\")", path);
    cleanup_commit(cl, free, resolved_path);
    return resolved_path;
}
#endif

static const char* cached_fb_adb_directory;

const char*
my_fb_adb_directory()
{
    SCOPED_RESLIST(rl);

    if (cached_fb_adb_directory)
        return cached_fb_adb_directory;

    const char* mydir;
    int mkdir_result;
#ifdef __ANDROID__
    mydir = xaprintf("%s/.fb-adb.%u",
                     DEVICE_TEMP_DIR,
                     (unsigned) getuid());
    mkdir_result = mkdir(mydir, 0700);
    if (mkdir_result == -1 && errno == EACCES) {
        // CWD hopefully in app data directory
        mydir = xaprintf("./.fb-adb.%u", (unsigned) getuid());
        mkdir_result = mkdir(mydir, 0700);
    }
#else
    const char* home = getenv("HOME");
    if (home == NULL)
        die(EINVAL, "HOME not set");
    mydir = xaprintf("%s/.fb-adb", home);
    mkdir_result = mkdir(mydir, 0700);
#endif
    if (mkdir_result == -1 && errno != EEXIST)
        die_errno("mkdir(\"%s\")", mydir);
    cached_fb_adb_directory = strdup(mydir);
    if (cached_fb_adb_directory == NULL)
        die_oom();
    return cached_fb_adb_directory;
}

void
unlink_cleanup(void* filename)
{
    (void) unlink((const char*) filename);
}

void
xflock(int fd, int operation)
{
    int ret;

    do {
        WITH_IO_SIGNALS_ALLOWED();
        ret = flock(fd, operation);
    } while (ret == -1 && errno == EINTR);

    if (ret < 0)
        die_errno("flock(%d,%d)", fd, operation);
}

struct growable_buffer {
    struct cleanup* cl;
    uint8_t* buf;
    size_t bufsz;
};

static void
resize_buffer(struct growable_buffer* gb, size_t new_size)
{
    struct cleanup* new_cl = cleanup_allocate();
    uint8_t* new_buf = realloc(gb->buf, new_size);
    if (new_buf == NULL)
        die_oom();
    cleanup_commit(new_cl, free, new_buf);
    cleanup_forget(gb->cl);
    gb->buf = new_buf;
    gb->cl = new_cl;
    gb->bufsz = new_size;
}

static void
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

char*
slurp_fd(int fd, size_t* nr_bytes_read_out)
{
    size_t n;
    size_t nr_bytes_read = 0;
    struct growable_buffer gb = { 0 };

    struct stat st;
    if (fstat(fd, &st) == 0 &&
        S_ISREG(st.st_mode) &&
        st.st_size > 0)
    {
        resize_buffer(&gb, st.st_size + 1);
    }

    do {
        size_t available_space = gb.bufsz - nr_bytes_read;
        if (available_space == 0) {
            grow_buffer_dwim(&gb);
            available_space = gb.bufsz - nr_bytes_read;
        }
        n = read_all(fd, gb.buf + nr_bytes_read, available_space);
        nr_bytes_read += n;
    } while (n > 0);

    resize_buffer(&gb, nr_bytes_read+1);
    gb.buf[nr_bytes_read] = '\0';
    if (nr_bytes_read_out != NULL)
        *nr_bytes_read_out = nr_bytes_read;
    return (char*) gb.buf;
}

char*
slurp_line(FILE* file, size_t* nr_bytes_read_out)
{
    size_t nr_bytes_read = 0;
    struct growable_buffer gb = { 0 };

    for (;;) {
        int c = getc(file);
        if (c == EOF) {
            if (feof(file)) return NULL;
            else die_errno("getc");
        }
        if (nr_bytes_read == gb.bufsz) {
            grow_buffer_dwim(&gb);
            assert(nr_bytes_read < gb.bufsz);
        }

        gb.buf[nr_bytes_read++] = c;
        if (c == '\n')
            break;
    }

    resize_buffer(&gb, nr_bytes_read+1);
    gb.buf[nr_bytes_read] = '\0';
    if (nr_bytes_read_out != NULL)
        *nr_bytes_read_out = nr_bytes_read;

    return (char*) gb.buf;
}

struct stat
xfstat(int fd)
{
    struct stat st;
    if (fstat(fd, &st) == -1)
        die_errno("fstat");
    return st;
}
