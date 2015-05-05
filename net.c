#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "util.h"
#include "net.h"

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
