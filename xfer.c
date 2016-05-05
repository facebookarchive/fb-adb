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
#include <stdint.h>
#include <assert.h>
#include <stddef.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include "util.h"
#include "autocmd.h"
#include "xfer.h"
#include "fs.h"
#include "constants.h"
#if FBADB_MAIN
# include "peer.h"
#endif

// This file describes a facility that file-transfer commands use to
// talk to each other.  This protocol runs on top of the more
// fundamental proto.h session protocol.

enum xfer_msg_type {
    XFER_MSG_STAT = 10,
    XFER_MSG_DATA,
};

#pragma pack(push, 1)
struct xfer_msg {
    uint8_t type;
    uint8_t pad_a;
    uint16_t pad_b;
    uint32_t pad_c;
    union {
        struct {
            uint64_t atime;
            uint64_t mtime;
            uint64_t size;
            uint32_t atime_ns;
            uint32_t mtime_ns;
            uint16_t ugo_bits;
        } stat;

        struct {
            uint32_t payload_size;
        } data;
    } u;
};
#pragma pack(pop)

#define XFER_MSG_SIZE(field)                      \
    (offsetof(struct xfer_msg, u.field) +         \
     sizeof (((struct xfer_msg*)0)->u.field))

static size_t
xfer_msg_size(uint8_t type)
{
    switch (type) {
        case XFER_MSG_STAT:
            return XFER_MSG_SIZE(stat);
        case XFER_MSG_DATA:
            return XFER_MSG_SIZE(data);
        default:
            die(ECOMM, "unknown message type %u", (unsigned) type);
    }
}

static struct xfer_msg
recv_xfer_msg(int from_peer)
{
    dbg("reading xfer msg from fd %d", from_peer);
    struct xfer_msg m;
    size_t hsz = offsetof(struct xfer_msg, u);
    if (read_all(from_peer, &m, hsz) < hsz)
        die(ECOMM, "short xfer message");
    dbg("... read message type=%u", (unsigned) m.type);
    size_t msize = xfer_msg_size(m.type);
    size_t remaining_bytes = msize - hsz;
    dbg("... reading remaining %u bytes of %u (hdr was %u)",
        (unsigned) remaining_bytes,
        (unsigned) msize,
        (unsigned) hsz);
    read_all(from_peer, &m.u, remaining_bytes);
    return m;
}

static void
send_xfer_msg(int to_peer, const struct xfer_msg* m)
{
    dbg("sending xfer message type=%u size=%u",
        (unsigned) m->type,
        (unsigned) xfer_msg_size(m->type));
    write_all(to_peer, m, xfer_msg_size(m->type));
}

static void
send_stat_packet(int to_peer, int xfer_fd)
{
    struct stat st;
    if (fstat(xfer_fd, &st) == -1)
        die_errno("fstat");
    struct xfer_msg m = {
        .type = XFER_MSG_STAT,
        .u.stat.atime = st.st_atime,
        .u.stat.mtime = st.st_mtime,
#ifdef HAVE_STRUCT_STAT_ST_ATIM
        .u.stat.atime_ns = st.st_atim.tv_nsec,
#endif
#ifdef HAVE_STRUCT_STAT_ST_MTIM
        .u.stat.mtime_ns = st.st_mtim.tv_nsec,
#endif
        .u.stat.size = st.st_size,
        .u.stat.ugo_bits = st.st_mode & 0777,
    };

    send_xfer_msg(to_peer, &m);
}

struct xfer_ctx {
    int from_peer;
    int to_peer;
    const struct cmd_xfer_stub_info* info;
};

static uint32_t
recv_data_header(int from_peer)
{
    struct xfer_msg m = recv_xfer_msg(from_peer);
    if (m.type != XFER_MSG_DATA)
        die(ECOMM, "unexpected message type %u", (unsigned) m.type);
    return m.u.data.payload_size;
}

static void
send_data_header(int to_peer, uint32_t size)
{
    struct xfer_msg m = {
        .type = XFER_MSG_DATA,
        .u.data.payload_size = size,
    };

    send_xfer_msg(to_peer, &m);
}

static uint64_t
copy_loop_posix_recv(
    int from_peer,
    int dest_fd)
{
    SCOPED_RESLIST(rl);
    struct growable_buffer buf = { 0 };
    uint64_t total_written = 0;
    size_t chunksz;

    do {
        chunksz = recv_data_header(from_peer);
        dbg("data chunk header chunksz=%u", (unsigned) chunksz);
        resize_buffer(&buf, chunksz);
        if (read_all(from_peer, buf.buf, chunksz) != chunksz)
            die(ECOMM, "unexpected EOF");
        write_all(dest_fd, buf.buf, chunksz);
        if (SATADD(&total_written, total_written, chunksz))
            die(ECOMM, "file size too large");
    } while (chunksz > 0);

    return total_written;
}

static void
copy_loop_posix_send(
    int to_peer,
    int source_fd)
{
    SCOPED_RESLIST(rl);
    size_t bufsz = 32 * 1024;
    uint8_t* buf = xalloc(bufsz);
    size_t nr_read;

    assert(bufsz <= UINT32_MAX);

    do {
        nr_read = read_all(source_fd, buf, bufsz);
        send_data_header(to_peer, nr_read);
        write_all(to_peer, buf, nr_read);
    } while (nr_read > 0);
}

static void
do_xfer_recv(const struct xfer_opts xfer_opts,
             const char* filename,
             const char* desired_basename,
             int from_peer)
{
    struct xfer_msg statm = recv_xfer_msg(from_peer);
    if (statm.type != XFER_MSG_STAT)
        die(ECOMM, "expected stat msg");

    struct cleanup* error_cl = cleanup_allocate();
    struct stat st;
    const char* parent_directory = NULL;
    const char* rename_to = NULL;
    const char* write_mode = NULL;
    int dest_fd;

    if (stat(filename, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            if (desired_basename == NULL)
                die(EISDIR, "\"%s\" is a directory", filename);
            parent_directory = filename;
            filename = xaprintf("%s/%s",
                                parent_directory,
                                desired_basename);
        } else if (S_ISREG(st.st_mode)) {
            if (st.st_nlink > 1)
                write_mode = "inplace";
        } else {
            write_mode = "inplace";
        }
    }

    if (parent_directory == NULL)
        parent_directory = xdirname(filename);

    if (write_mode == NULL)
        write_mode = xfer_opts.write_mode;

    bool atomic;
    bool automatic_mode = false;
    if (write_mode == NULL) {
        automatic_mode = true;
        atomic = true;
    } else if (strcmp(write_mode, "atomic") == 0) {
        atomic = true;
    } else if (strcmp(write_mode, "inplace") == 0) {
        atomic = false;
    } else {
        die(EINVAL, "unknown write mode \"%s\"", write_mode);
    }

    bool regular_file = true;
    bool preallocated = false;
    bool chmod_explicit = false;
    mode_t chmod_explicit_modes = 0;

    if (xfer_opts.preserve) {
        chmod_explicit = true;
        chmod_explicit_modes = statm.u.stat.ugo_bits;
    }

    if (xfer_opts.mode) {
        char* endptr = NULL;
        errno = 0;
        unsigned long omode = strtoul(xfer_opts.mode, &endptr, 8);
        if (errno != 0 || *endptr != '\0' || (omode &~ 0777) != 0)
            die(EINVAL, "invalid mode bits: %s", xfer_opts.mode);
        chmod_explicit = true;
        chmod_explicit_modes = (mode_t) omode;
    }

    mode_t creat_mode = (chmod_explicit_modes ? 0200 : 0666);

    if (atomic) {
        rename_to = filename;
        filename =
            xaprintf("%s/.%s.fb-adb-%s",
                     xdirname(filename),
                     xbasename(filename),
                     gen_hex_random(ENOUGH_ENTROPY));
        dest_fd = try_xopen(
            filename,
            O_CREAT | O_WRONLY | O_EXCL,
            creat_mode);
        if (dest_fd == -1) {
            if (errno == EACCES && automatic_mode) {
                atomic = false;
                filename = rename_to;
                rename_to = NULL;
            } else {
                die_errno("open(\"%s\")", filename);
            }
        }
    }

    if (!atomic) {
        dest_fd = xopen(filename, O_WRONLY | O_CREAT | O_TRUNC, creat_mode);
        if (!S_ISREG(xfstat(dest_fd).st_mode))
            regular_file = false;
    }

    if (regular_file)
        cleanup_commit(error_cl, unlink_cleanup, filename);

    if (regular_file && statm.u.stat.size > 0)
        preallocated = fallocate_if_supported(
            dest_fd,
            statm.u.stat.size);

    uint64_t total_written = copy_loop_posix_recv(from_peer, dest_fd);

    if (preallocated && total_written < statm.u.stat.size)
        xftruncate(dest_fd, total_written);

    if (xfer_opts.preserve) {
        struct timeval times[2] = {
            { statm.u.stat.atime, statm.u.stat.atime_ns / 1000 },
            { statm.u.stat.mtime, statm.u.stat.mtime_ns / 1000 },
        };
#ifdef HAVE_FUTIMES
        if (futimes(dest_fd, times) == -1)
            die_errno("futimes");
#else
        if (utimes(filename, times) == -1)
            die_errno("times");
#endif
    }

    if (chmod_explicit)
        if (fchmod(dest_fd, chmod_explicit_modes) == -1)
            die_errno("fchmod");

    if (xfer_opts.sync)
        xfsync(dest_fd);

    if (rename_to)
        xrename(filename, rename_to);

    if (xfer_opts.sync)
        xfsync(xopen(parent_directory, O_DIRECTORY|O_RDONLY, 0));

    cleanup_forget(error_cl);
}

static void
do_xfer_send(int to_peer, const char* filename)
{
    int fd;

    if (!strcmp(filename, "-"))
        fd = xdup(STDIN_FILENO);
    else
        fd = xopen(filename, O_RDONLY, 0);
    dbg("opened %s as %d", filename, fd);
    send_stat_packet(to_peer, fd);
    dbg("sent stat packet; entering copy loop");
    hint_sequential_access(fd);
    copy_loop_posix_send(to_peer, fd);
}

static void
do_xfer(struct xfer_ctx* ctx)
{
    const struct cmd_xfer_stub_info* info = ctx->info;

    dbg("do_xfer in %s mode filename=[%s] desired_basename=[%s]",
        info->mode, info->filename, info->desired_basename);

    if (strcmp(info->mode, "recv") == 0) {
        do_xfer_recv(info->xfer,
                     info->filename,
                     info->desired_basename,
                     ctx->from_peer);
    } else if (strcmp(info->mode, "send") == 0) {
        do_xfer_send(ctx->to_peer, info->filename);
    } else {
        die(EINVAL, "invalid xfer mode %s", info->mode);
    }
}

int
xfer_stub_main(const struct cmd_xfer_stub_info* info)
{
    struct xfer_ctx ctx = {
        .from_peer = STDIN_FILENO,
        .to_peer = STDOUT_FILENO,
        .info = info,
    };

    set_prgname("");
    do_xfer(&ctx);
    return 0;
}

#if FBADB_MAIN
int
xfer_handle_command(
    const struct start_peer_info* spi,
    const struct cmd_xfer_stub_info* local,
    const struct cmd_xfer_stub_info* remote)
{
    struct child* peer = start_peer(
        spi,
        make_args_cmd_xfer_stub(
            CMD_ARG_NAME | CMD_ARG_FORWARDED,
            remote));

    struct xfer_ctx ctx = {
        .from_peer = peer->fd[1]->fd,
        .to_peer = peer->fd[0]->fd,
        .info = local,
    };

    do_xfer(&ctx);
    child_wait_die_on_error(peer);
    return 0;
}
#endif
