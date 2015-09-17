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
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <dirent.h>
#include <sys/file.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include "util.h"

// Commit a cleanup object to closing the given file descriptor.
void cleanup_commit_close_fd(struct cleanup* cl, int fd);

// Open a file.  The returned file descriptor is owned by the
// current reslist.
int xopen(const char* pathname, int flags, mode_t mode);
int try_xopen(const char* pathname, int flags, mode_t mode);

// Close a file descriptor.  Fail if FD is not an open file
// descriptor.  Do not use to close file descriptors owned
// by reslists.
void xclose(int fd);

// Allocate a pipe.  The file descriptors are owned by the
// current reslits.
void xpipe(int* read_end, int* write_end);

// Duplicate a file descriptor.  The new file descriptor is owned by
// the current reslist.
int xdup(int fd);
int xdup3nc(int oldfd, int newfd, int flags);

// Open a file descriptor as a stream.  The returned FILE object is
// owned by the current reslist.  It does _not_ own FD.  The caller
// must guarante that FD remains alive for however long the resulting
// FILE* is in use.
FILE* xfdopen(int fd, const char* mode);

// All file descriptors we allocate are configured to be
// close-on-exit.  This routine allows FD to be inherited across exec.
void allow_inherit(int fd);

char* xreadlink(const char* path);

// A FDH (File Descriptor Handle) is a package of a file descriptor
// and a reslist that owns it.  It allows us to allocate an file
// descriptor owned by a reslist and close that file descriptor before
// its owning reslist is destroyed.

struct fdh {
    struct reslist* rl; // Owns both fd and fdh
    int fd;
};

// Duplicate an existing FD as an FDH
struct fdh* fdh_dup(int fd);

// Deallocate an FDH, closing its file descriptor.  FDH is invalid
// after this call.
void fdh_destroy(struct fdh* fdh);

enum blocking_mode { blocking, non_blocking };
enum blocking_mode fd_set_blocking_mode(int fd, enum blocking_mode mode);

void hack_reopen_tty(int fd);

// Read SZ bytes from FD into BUF, retrying on EINTR.
// May return short read on EOF.
size_t read_all(int fd, void* buf, size_t sz);

// Write SZ bytes to FD, retrying on EINTR.
void write_all(int fd, const void* buf, size_t sz);

#ifndef HAVE_DUP3
int dup3(int oldfd, int newfd, int flags);
#endif

#define XPPOLL_LINUX_SYSCALL 1
#define XPPOLL_KQUEUE 2
#define XPPOLL_SYSTEM 3
#define XPPOLL_STUPID_WRAPPER 4

#if defined(__linux__)
# define XPPOLL XPPOLL_LINUX_SYSCALL
#elif defined(HAVE_KQUEUE)
# define XPPOLL XPPOLL_KQUEUE
#elif defined(HAVE_PPOLL)
# define XPPOLL XPPOLL_SYSTEM
# define XPPOLL_BROKEN 1
#else
# define XPPOLL XPPOLL_STUPID_WRAPPER
# define XPPOLL_BROKEN 1
#endif

// See ppoll(2) or ppoll(3).  If XPPOLL_BROKEN is defined, this
// routine may not atomically set SIGMASK and begin waiting, so you'll
// need to arrange for some other wakeup mechanism to avoid racing
// against signal delivery.
int xppoll(struct pollfd *fds, nfds_t nfds,
           const struct timespec *timeout_ts,
           const sigset_t *sigmask);

int xpoll(struct pollfd* fds, nfds_t nfds, int timeout);

#ifndef HAVE_MKOSTEMP
int mkostemp(char *template, int flags);
#endif

int xnamed_tempfile(const char** name);
void replace_stdin_stdout_with_dev_null(void);

#ifndef NDEBUG
void assert_cloexec(int fd);
#else
# define assert_cloexec(_fd) ((void)(_fd))
#endif

int merge_O_CLOEXEC_into_fd_flags(int fd, int flags);

// See dirname(3)
char* xdirname(const char* path);

// See basename(3)
char* xbasename(const char* path);

// Try to make sure FD has SIZE bytes available total; if the
// filesystem or OS doesn't support preallocation, return false.
// Otherwise, return true on success or die on failure.
bool fallocate_if_supported(int fd, uint64_t size);

void xfsync(int fd);
void xftruncate(int fd, uint64_t size);
void xrename(const char* old, const char* new);

void hint_sequential_access(int fd);
void _fs_on_init(void);

void xputc(char c, FILE* out);
void xputs(const char* s, FILE* out);
void xflush(FILE* out);
void xfwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream);
__attribute__((format(printf,2,3)))
void xprintf(FILE* out, const char* fmt, ...);

const char* system_tempdir(void);

struct sha256_hash {
    uint8_t digest[32];
};
struct sha256_hash sha256_fd(int fd);
void xrewindfd(int fd);

#ifdef HAVE_REALPATH
const char* xrealpath(const char* path);
#endif

const char* my_fb_adb_directory(void);
void unlink_cleanup(void* filename);
void xflock(int fd, int operation);

// Read FD to EOF, returning a pointer to the bytes we read, which we
// NUL-terminate.  (Of course, the string will appear to terminate
// early if we read a NUL byte from the FD.)
char* slurp_fd(int fd, size_t* nr_bytes_read_out);

struct growable_buffer slurp_fd_buf(int fd);

// Read a line into a heap-allocated and NUL-terminated buffer.
// The line terminator, if one was present, is included in the
// returned string.  On EOF, return NULL.
char* slurp_line(FILE* file, size_t* nr_bytes_read_out);

struct stat xfstat(int fd);
struct stat xstat(const char* path);

int xF_GETFL(int fd);
void xF_SETFL(int fd, int flags);

DIR* xopendir(const char* path);
