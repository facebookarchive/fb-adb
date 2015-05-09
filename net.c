#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/wait.h>
#include "util.h"
#include "net.h"
#include "child.h"

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC O_CLOEXEC
#endif

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
        WITH_IO_SIGNALS_ALLOWED();
        rc = connect(fd, &addr->addr, addr->size);
    } while (rc == -1 && errno == EINTR);

    if (rc == -1)
        die_errno("connect");
}

void
xlisten(int fd, int backlog)
{
    if (listen(fd, backlog) == -1)
        die_errno("listen");
}

void
xbind(int fd, const struct addr* addr)
{
    if (bind(fd, &addr->addr, addr->size) == -1)
        die_errno("bind");
}

static void
xgetaddrinfo_cleanup(void* data)
{
    freeaddrinfo((struct addrinfo*) data);
}

struct addrinfo*
xgetaddrinfo(const char* node,
             const char* service,
             const struct addrinfo* hints)
{
    int rc;
    struct cleanup* cl = cleanup_allocate();
    struct addrinfo* res = NULL;

    do {
        rc = getaddrinfo(node, service, hints, &res);
    } while (rc == EAI_SYSTEM && errno == EINTR);

    if (rc == EAI_SYSTEM)
        die_errno("getaddrinfo");

    if (rc != 0)
        die(ENOENT, "getaddrinfo failed: %s", gai_strerror(rc));

    cleanup_commit(cl, xgetaddrinfo_cleanup, res);
    return res;
}

struct addr*
addrinfo2addr(const struct addrinfo* ai)
{
    size_t allocsz = offsetof(struct addr, addr);
    if (SATADD(&allocsz, allocsz, ai->ai_addrlen))
        die(EINVAL, "address too long");

    struct addr* a = xalloc(allocsz);
    a->size = ai->ai_addrlen;
    memcpy(&a->addr, ai->ai_addr, ai->ai_addrlen);
    return a;
}

void
xsetsockopt(int fd, int level, int opname,
            void* optval, socklen_t optlen)
{
    if (setsockopt(fd, level, opname, optval, optlen) == -1)
        die_errno("setsockopt");
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
        WITH_IO_SIGNALS_ALLOWED();
#ifdef HAVE_ACCEPT4
        s = accept4(server_socket, NULL, NULL, SOCK_CLOEXEC);
#else
        s = accept(server_socket, NULL, NULL);
#endif
    } while (s == -1 && errno == EINTR);

    if (s == -1)
        die_errno("accept");

#ifndef HAVE_ACCEPT4
    merge_O_CLOEXEC_into_fd_flags(s, O_CLOEXEC);
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

void
disable_tcp_nagle(int fd)
{
    int on = 1;
    xsetsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
}

struct write_all_or_die {
    int fd;
    const void* buf;
    size_t sz;
};

static void
write_all_or_die_1(void* data)
{
    struct write_all_or_die* waod = data;
    write_all(waod->fd, waod->buf, waod->sz);
}

static void
write_all_or_die(int fd, const void* buf, size_t sz)
{
    struct write_all_or_die waod = {
        .fd = fd,
        .buf = buf,
        .sz = sz,
    };

    if (catch_error(write_all_or_die_1, &waod, NULL))
        abort();
}

struct xgai {
    const char* node;
    const char* service;
    const struct addrinfo* hints;
};

static void
write_blob(int fd, const void* data, size_t sz)
{
    write_all(fd, &sz, sizeof (sz));
    write_all(fd, data, sz);
}

static void
xgai_preexec_1(void* data)
{
    struct xgai* xa = data;
    int fd = STDOUT_FILENO;
    for (struct addrinfo* ai =
             xgetaddrinfo(xa->node, xa->service, xa->hints);
         ai;
         ai = ai->ai_next)
    {
        write_blob(fd, ai, sizeof (*ai));
        write_blob(fd, ai->ai_addr, ai->ai_addrlen);
        if (ai->ai_canonname)
            write_blob(fd, ai->ai_canonname, strlen(ai->ai_canonname)+1);
    }
}

static void
xgai_preexec(void* data)
{
    sigset_t no_signals;
    sigemptyset(&no_signals);
    memcpy(&signals_unblock_for_io, &no_signals, sizeof (sigset_t));

    struct errinfo ei = { .want_msg = true };
    if (catch_error(xgai_preexec_1, data, &ei)) {
        write_all_or_die(2, ei.msg, strlen(ei.msg));
        _exit(1);
    }

    _exit(0);
}

static void*
decode_blob(uint8_t** data_inout, size_t* sz_out, uint8_t* data_end)
{
    uint8_t* data = *data_inout;
    size_t sz;
    if (data_end - data < sizeof (sz))
        die(ECOMM, "truncated data");

    memcpy(&sz, data, sizeof (sz));
    data += sizeof (sz);

    if (data_end - data < sz)
        die(ECOMM, "truncated data");

    void* blob = data;
    data += sz;

    *data_inout = data;
    *sz_out = sz;
    return blob;
}

struct addrinfo*
xgetaddrinfo_interruptible(
    const char* node,
    const char* service,
    const struct addrinfo* hints)
{
    struct xgai xa = {
        .node = node,
        .service = service,
        .hints = hints,
    };

    struct child_start_info csi = {
        .flags = ( CHILD_NULL_STDIN ),
        .pre_exec = xgai_preexec,
        .pre_exec_data = &xa,
    };

    struct child_communication* com =
        child_communicate(child_start(&csi), NULL, 0);

    bool success = WIFEXITED(com->status) && WEXITSTATUS(com->status) == 0;
    if (!success) {
        if (WIFEXITED(com->status)) {
            die(ENOENT,
                "%.*s",
                (int) XMIN(com->out[1].nr, INT_MAX),
                com->out[1].bytes);
        } else if (WIFSIGNALED(com->status)) {
            die(ENOENT,
                "getaddrinfo failed with signal %d",
                WTERMSIG(com->status));
        } else {
            die(ENOENT, "unknown status from resolver process");
        }
    }

    // Subprocesses supposedly succeeded.  Read from the serialized
    // GAI information.

    uint8_t* data = com->out[0].bytes;
    uint8_t* data_end = data + com->out[0].nr;
    struct addrinfo* ai_list = NULL;
    struct addrinfo** next = &ai_list;

    while (data < data_end) {
        struct addrinfo* ai;
        size_t sz;

        ai = decode_blob(&data, &sz, data_end);
        if (sz != sizeof (*ai))
            die(ECOMM, "gai protocol error");

        ai->ai_addr = decode_blob(&data, &sz, data_end);
        if (sz != ai->ai_addrlen)
            die(ECOMM, "gai protocol error");

        if (ai->ai_canonname)
            ai->ai_canonname = decode_blob(&data, &sz, data_end);

        *next = ai;
        next = &ai->ai_next;
    }

    return ai_list;
}
