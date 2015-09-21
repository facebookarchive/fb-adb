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
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <limits.h>
#include <fnmatch.h>
#include <pwd.h>
#include <grp.h>
#include <sys/queue.h>
#include "util.h"
#include "autocmd.h"
#include "fs.h"

FORWARD(ctar);

#if !FBADB_MAIN

#define TAR_BLOCK_SIZE 512

struct tar_hdr_v7 {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char checksum[8];
    char typeflag;
    char linkname[100];
};

struct tar_hdr_ustar {
    struct tar_hdr_v7 v7;
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char pad[12];
};

struct tar_hdr_gnu {
    struct tar_hdr_v7 v7;
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char offset[12];
    char longnames[4];
    char unused[1];
    struct {
        char offset[12];
        char numbytes[12];
    } sparse[4];
    char isextended[1];
    char realsize[12];
    char pad[17];
};

union tar_block {
    struct tar_hdr_v7 v7;
    struct tar_hdr_ustar ustar;
    struct tar_hdr_gnu gnu;
    char data[512];
};

enum pattern_mode {
    PATTERN_MUST_MATCH,
    PATTERN_MUST_NOT_MATCH,
};

enum pattern_kind {
    PATTERN_FNMATCH,
    PATTERN_REGMATCH,
};

struct pattern {
    STAILQ_ENTRY(pattern) link;
    regex_t* regex_pattern;
    const char* fnmatch_pattern;
    enum pattern_mode mode;
    enum pattern_kind kind;
};

struct ctar_ctx {
    uint8_t* buf;
    size_t bufsz;
    bool force;
    STAILQ_HEAD(, pattern) patterns;
};

static uint64_t
octal_field_max(unsigned octal_digits)
{
    assert(octal_digits >= 1);
    uint64_t max_value = 8;
    for (size_t i = 0; i < octal_digits - 1; ++i)
        max_value *= 8;
    return max_value - 1;
}

#define FIELD_ALLOW_BASE256 (1<<0)

static void
fill_octal_field(
    const char* path,
    const char* field_name,
    char* field,
    size_t field_size,
    uint64_t value,
    unsigned flags)
{
    assert(field_size >= 2);
    unsigned octal_digits = field_size - 1;
    uint64_t max_value = octal_field_max(octal_digits);
    if (value <= max_value) {
        sprintf(field, "%0*llo",
                (int) octal_digits,
                (unsigned long long) value);
        value = 0;
    } else if (flags & FIELD_ALLOW_BASE256) {
        uint8_t* start = (uint8_t*) field;
        uint8_t* end = start + field_size;
        uint8_t* pos = end - 1;
        while (value != 0 && pos != start) {
            *pos = value & 0xFF;
            value >>= 8;
            pos -= 1;
        }
        if (value < 0x40) {
            *pos = value | 0x80;
            value = 0;
        }
    }

    if (value != 0)
        die(E2BIG, "%s: %s too large", path, field_name);
}

static void
fill_header_checksum(union tar_block* hdr)
{
    memset(hdr->v7.checksum, ' ', sizeof (hdr->v7.checksum));
    uint8_t* pos = (uint8_t*) hdr;
    uint8_t* end = pos + sizeof (*hdr);
    // N.B. The checksum cannot overflow either the unsigned variable
    // or the octal representation: the maximum value of a byte is
    // 255, and we only have 512 bytes, yielding a maximum sum of
    // 130560.  We can store a value up to 8^6 - 1, or 262143.
    unsigned total = 0;
    while (pos < end)
        total += *pos++;
    sprintf(hdr->v7.checksum, "%06o ", total);
}

static void
tar_copy_bytes_padded(struct ctar_ctx* ctx,
                      int file,
                      uint64_t bytes_left,
                      const char* path)
{
    uint8_t* buf = ctx->buf;
    size_t bufsz = ctx->bufsz;
    while (bytes_left > 0) {
        size_t to_read = bufsz;
        if (to_read > bytes_left)
            to_read = bytes_left;
        size_t chunksz = read_all(file, buf, to_read);
        if (chunksz == 0)
            die(EINVAL, "short %llu bytes reading %s",
                (unsigned long long) bytes_left, path);
        bytes_left -= chunksz;
        if (bytes_left == 0 && chunksz % TAR_BLOCK_SIZE) {
            size_t pad = TAR_BLOCK_SIZE - (chunksz % TAR_BLOCK_SIZE);
            memset(&buf[chunksz], 0, pad);
            chunksz += pad;
        }
        write_all(STDOUT_FILENO, buf, chunksz);
    }
}

static void
write_ctar_header(struct ctar_ctx* ctx,
                  const char* path,
                  const struct stat* st)
{
    union tar_block hdr;
    _Static_assert(sizeof (hdr) == TAR_BLOCK_SIZE, "tar spec");
    memset(&hdr, 0, sizeof (hdr));

    const char* orig_path = path;
    while (path[0] == '/')
        path += 1;
    if (path[0] == '\0')
        path = ".";
    const char* prefix = path;
    const char* prefix_end = path;
    const char* path_end = path + strlen(path);
    size_t maximum_path_length = sizeof (hdr.v7.name);
    size_t maximum_prefix_length = sizeof (hdr.ustar.prefix);

    if (S_ISDIR(st->st_mode))
        maximum_prefix_length -= 1; // Need room for trailing slash

    while (path_end - path > maximum_path_length &&
           prefix_end - prefix < maximum_prefix_length)
    {
        const char* sep = strchr(path, '/');
        if (sep == NULL)
            break;
        path = sep + 1;
        prefix_end = sep;
    }

    if (path_end - path > maximum_path_length ||
        prefix_end - prefix > maximum_path_length)
    {
        die(EINVAL, "path too long: %s", orig_path);
    }

    memcpy(hdr.v7.name, path, path_end - path);
    memcpy(hdr.ustar.prefix, prefix, prefix_end - prefix);

    bool is_device = false;

    switch (st->st_mode & S_IFMT) {
        case S_IFSOCK: {
            return; // Silently skip sockets
        }
        case S_IFLNK: {
            hdr.v7.typeflag = '2';
            char* link_target = xreadlink(orig_path);
            size_t link_target_length = strlen(link_target);
            if (link_target_length > sizeof (hdr.v7.linkname))
                die(E2BIG, "link target too long: %s", link_target);
            memcpy(hdr.v7.linkname, link_target, link_target_length);
            break;
        }
        case S_IFREG: {
            hdr.v7.typeflag = '0';
            break;
        }
        case S_IFBLK: {
            hdr.v7.typeflag = '4';
            is_device = true;
            break;
        }
        case S_IFDIR: {
            hdr.v7.typeflag = '5';
            hdr.v7.name[path_end - path] = '/';
            break;
        }
        case S_IFCHR: {
            hdr.v7.typeflag = '3';
            is_device = true;
            break;
        }
        case S_IFIFO: {
            hdr.v7.typeflag = '6';
            break;
        }
        default: {
            die(EINVAL,
                "unknown type %u for %s",
                (unsigned) st->st_mode & S_IFMT,
                path);
        }
    }

    fill_octal_field(path, "mode",
                     hdr.v7.mode, sizeof (hdr.v7.mode),
                     st->st_mode & 07777, 0);
    fill_octal_field(path, "uid",
                     hdr.v7.uid, sizeof (hdr.v7.uid),
                     st->st_uid, FIELD_ALLOW_BASE256);
    fill_octal_field(path, "gid",
                     hdr.v7.gid, sizeof (hdr.v7.gid),
                     st->st_gid, FIELD_ALLOW_BASE256);
    fill_octal_field(path, "size",
                     hdr.v7.size, sizeof (hdr.v7.size),
                     S_ISREG(st->st_mode) ? st->st_size : 0,
                     FIELD_ALLOW_BASE256);
    fill_octal_field(path, "mtime",
                     hdr.v7.mtime, sizeof (hdr.v7.mtime),
                     st->st_mtime, FIELD_ALLOW_BASE256);

    if (is_device) {
        fill_octal_field(path, "devmajor",
                         hdr.ustar.devmajor, sizeof (hdr.ustar.devmajor),
                         major(st->st_dev), 0);
        fill_octal_field(path, "devminor",
                         hdr.ustar.devminor, sizeof (hdr.ustar.devminor),
                         minor(st->st_dev), 0);
    }

    struct passwd* user = getpwuid(st->st_uid);
    if (user != NULL) {
        size_t pw_name_length = strlen(user->pw_name);
        if (pw_name_length < sizeof (hdr.ustar.uname) - 1)
            memcpy(hdr.ustar.uname, user->pw_name, pw_name_length);
    }

    struct group* group = getgrgid(st->st_gid);
    if (group != NULL) {
        size_t gr_name_length = strlen(group->gr_name);
        if (gr_name_length < sizeof (hdr.ustar.gname) - 1)
            memcpy(hdr.ustar.gname, group->gr_name, gr_name_length);
    }

    sprintf(hdr.ustar.magic, "ustar");
    fill_header_checksum(&hdr);
    write_all(STDOUT_FILENO, &hdr, sizeof (hdr));
}

static bool
should_include_in_archive(struct ctar_ctx* ctx, const char* path)
{
    struct pattern* pat;
    STAILQ_FOREACH(pat, &ctx->patterns, link) {
        bool match;
        if (pat->kind == PATTERN_FNMATCH) {
            match = fnmatch(pat->fnmatch_pattern, path, 0) == 0;
        } else {
            assert(pat->kind == PATTERN_REGMATCH);
            match = regexec(pat->regex_pattern, path, 0, NULL, 0) == 0;
        }

        if (pat->mode == PATTERN_MUST_MATCH && !match)
            return false;
        if (pat->mode == PATTERN_MUST_NOT_MATCH && match)
            return false;
    }

    return true;
}

static void write_ctar_file(struct ctar_ctx* ctx, const char* path);

void
write_ctar_file_2(struct ctar_ctx* ctx, const char* path)
{
    SCOPED_RESLIST(rl);

    struct stat st;
    if (lstat(path, &st) == -1)
        die_errno("lstat(\"%s\")", path);

    size_t path_length = strlen(path);
    assert(path_length > 0);
    if (path[path_length - 1] == '/') {
        char* path_cpy = xstrdup(path);
        rtrim(path_cpy, &path_length, "/");
        path = path_cpy;
    }

    bool include_in_archive = should_include_in_archive(ctx, path);
    if (include_in_archive)
        write_ctar_header(ctx, path, &st);

    if (S_ISREG(st.st_mode) && include_in_archive) {
        int file = xopen(path, O_RDONLY, 0);
        tar_copy_bytes_padded(ctx, file, st.st_size, path);
    }

    if (S_ISDIR(st.st_mode)) {
        DIR* dir = xopendir(path);
        struct dirent* ent;
        while ((ent = readdir(dir)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 ||
                strcmp(ent->d_name, "..") == 0)
            {
                continue;
            }

            SCOPED_RESLIST(rl_sub);
            write_ctar_file(ctx, xaprintf("%s/%s", path, ent->d_name));
        }
    }
}

struct write_ctar_file_ctx {
    struct ctar_ctx* ctx;
    const char* path;
};

static void
write_ctar_file_1(void* data)
{
    struct write_ctar_file_ctx* wctx = data;
    write_ctar_file_2(wctx->ctx, wctx->path);
}

void
write_ctar_file(struct ctar_ctx* ctx, const char* path)
{
    if (ctx->force) {
        struct write_ctar_file_ctx wctx = {
            .ctx = ctx,
            .path = path
        };
        (void) catch_error(write_ctar_file_1, &wctx, NULL);
    } else {
        write_ctar_file_2(ctx, path);
    }
}

int
ctar_main(const struct cmd_ctar_info* info)
{
    struct ctar_ctx ctx = { 0 };
    ctx.bufsz = 64*1024;
    ctx.buf = xalloc(ctx.bufsz);
    assert(ctx.bufsz % TAR_BLOCK_SIZE == 0);
    ctx.force = info->ctar.ignore_errors;
    STAILQ_INIT(&ctx.patterns);

    if (info->ctar.excludes == NULL)
        goto no_patterns;

    for (const char* pattern_arg = strlist_rewind(info->ctar.excludes);
         pattern_arg != NULL;
         pattern_arg = strlist_next(info->ctar.excludes))
    {
        struct pattern* pat = xcalloc(sizeof (*pat));

        if (string_starts_with_p(pattern_arg, "exclude=")) {
            pat->mode = PATTERN_MUST_NOT_MATCH;
            pat->kind = PATTERN_FNMATCH;
            pattern_arg += strlen("exclude=");
        } else if (string_starts_with_p(pattern_arg, "exclude-regex=")) {
            pat->mode = PATTERN_MUST_NOT_MATCH;
            pat->kind = PATTERN_REGMATCH;
            pattern_arg += strlen("exclude-regex=");
        } else if (string_starts_with_p(pattern_arg, "include=")) {
            pat->mode = PATTERN_MUST_MATCH;
            pat->kind = PATTERN_FNMATCH;
            pattern_arg += strlen("include=");
        } else if (string_starts_with_p(pattern_arg, "include-regex=")) {
            pat->mode = PATTERN_MUST_MATCH;
            pat->kind = PATTERN_REGMATCH;
            pattern_arg += strlen("include-regex=");
        } else {
            abort();
        }

        if (pat->kind == PATTERN_REGMATCH) {
            pat->regex_pattern = xregcomp(pattern_arg, REG_EXTENDED);
        } else {
            pat->fnmatch_pattern = xstrdup(pattern_arg);
        }

        STAILQ_INSERT_TAIL(&ctx.patterns, pat, link);
    }

    no_patterns:;

    const char* const* paths = info->paths;
    while (paths && *paths != NULL)
        write_ctar_file(&ctx, *paths++);

    union tar_block hdr;
    memset(&hdr, 0, sizeof (hdr));
    write_all(STDOUT_FILENO, &hdr, sizeof (hdr));
    write_all(STDOUT_FILENO, &hdr, sizeof (hdr));
    return 0;
}
#endif
