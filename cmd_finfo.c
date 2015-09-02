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
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "util.h"
#include "autocmd.h"
#include "json.h"
#include "sha2.h"
#include "argv.h"

FORWARD(finfo);

#if !FBADB_MAIN

enum finfo_op_state {
    FINFO_OP_DISABLED,
    FINFO_OP_ENABLED
};

typedef void (*finfo_op_fn)(struct json_writer*, const char*, void*);

struct finfo_op {
    const char* name;
    enum finfo_op_state state;
    finfo_op_fn fn;
    void* fndata;
};

static void emit_finfo_op(
    struct json_writer* writer,
    const char* filename,
    finfo_op_fn fn,
    void* fndata);

static void finfo_ls(struct json_writer*, const char*, void*);

static void
finfo_stat_common(struct json_writer* writer,
                  const char* filename,
                  const char* statfn_name,
                  int (*statfn)(const char*, struct stat*))
{
    struct stat stat;
    if (statfn(filename, &stat) == -1)
        die_errno("%s", statfn_name);

    json_begin_object(writer);

    // We provide a symbolic mode in POSIX ls(1) format.  See the
    // POSIX specification for ls.
    mode_t mode = stat.st_mode;
    char sm[sizeof ("-rw-r--r--")];
    switch (mode & S_IFMT) {
        case S_IFSOCK:
            sm[0] = 's'; break;
        case S_IFLNK:
            sm[0] = 'l'; break;
        case S_IFREG:
            sm[0] = '-'; break;
        case S_IFBLK:
            sm[0] = 'b'; break;
        case S_IFDIR:
            sm[0] = 'd'; break;
        case S_IFCHR:
            sm[0] = 'c'; break;
        case S_IFIFO:
            sm[0] = 'p'; break;
        default:
            sm[0] = '?'; break;
    }
    sm[1] = (mode & S_IRUSR) ? 'r' : '-';
    sm[2] = (mode & S_IWUSR) ? 'w' : '-';
    if (!(mode & S_IXUSR) && (mode & S_ISUID))
        sm[3] = 'S';
    else if ((mode & S_IXUSR) && (mode & S_ISUID))
        sm[3] = 's';
    else
        sm[3] = (mode & S_IXUSR) ? 'x' : '-';
    sm[4] = (mode & S_IRGRP) ? 'r' : '-';
    sm[5] = (mode & S_IWGRP) ? 'w' : '-';
    if (!(mode & S_IXGRP) && (mode & S_ISGID))
        sm[6] = 'S';
    else if ((mode & S_IXGRP) && (mode & S_ISGID))
        sm[6] = 's';
    else
        sm[6] = (mode & S_IXGRP) ? 'x' : '-';
    sm[7] = (mode & S_IROTH) ? 'r' : '-';
    sm[8] = (mode & S_IWOTH) ? 'w' : '-';
    if (sm[0] == 'd' && !(mode & S_IXOTH) && (mode & S_ISVTX))
        sm[9] = 'T';
    else if (sm[0] == 'd' && (mode & S_IXOTH) && (mode & S_ISVTX))
        sm[9] = 't';
    else
        sm[9] = (mode & S_IXOTH) ? 'x' : '-';
    sm[10] = '\0';
    json_begin_field(writer, "modes");
    json_emit_string(writer, sm);

#define F(field) ({                             \
        json_begin_field(writer, #field);        \
        json_emit_u64(writer, (uint64_t) stat.field);   \
        })
    F(st_dev);
    F(st_ino);
    F(st_mode);
    F(st_nlink);
    F(st_uid);
    F(st_gid);
#ifdef HAVE_STRUCT_STAT_ST_RDEV
    F(st_rdev);
#endif
    F(st_size);
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
    F(st_blksize);
#endif
#ifdef HAVE_STRUCT_STAT_ST_BLOCKS
    F(st_blocks);
#endif
    F(st_atime);
#ifdef HAVE_STRUCT_STAT_ST_ATIM
    F(st_atim.tv_nsec);
#endif
    F(st_mtime);
#ifdef HAVE_STRUCT_STAT_ST_MTIM
    F(st_mtim.tv_nsec);
#endif
    F(st_ctime);
#ifdef HAVE_STRUCT_STAT_ST_CTIM
    F(st_ctim.tv_nsec);
#endif
#undef F
    json_end_object(writer);
}

static void
finfo_stat(struct json_writer* writer, const char* filename, void* data)
{
    finfo_stat_common(writer, filename, "stat", stat);
}

static void
finfo_lstat(struct json_writer* writer, const char* filename, void* data)
{
    finfo_stat_common(writer, filename, "lstat", lstat);
}

static void
finfo_readlink(struct json_writer* writer, const char* filename, void* data)
{
    json_emit_string(writer, xreadlink(filename));
}

static char*
hex_sha256_fd(int fd)
{
    SCOPED_RESLIST(rl);

    size_t bufsz = 32768;
    uint8_t* buf = xalloc(bufsz);
    size_t nr_read;
    SHA256_CTX sha256;

    SHA256_Init(&sha256);

    while ((nr_read = read_all(fd, buf, bufsz)) > 0) {
        SHA256_Update(&sha256, buf, nr_read);
    }

    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_Final(digest, &sha256);

    WITH_CURRENT_RESLIST(rl->parent);
    return hex_encode_bytes(digest, sizeof (digest));
}

static void
finfo_sha256(struct json_writer* writer, const char* filename, void* data)
{
    json_emit_string(writer, hex_sha256_fd(xopen(filename, O_RDONLY, 0)));
}

static void
finfo_execp(struct json_writer* writer, const char* filename, void* data)
{
    if (access(filename, X_OK) != 0)
        die_errno("access");
    json_emit_bool(writer, true);
}

static void
cleanup_closedir(void* data)
{
    closedir((DIR*) data);
}

#ifdef HAVE_STRUCT_DIRENT_D_TYPE
static const char*
dirent_type_to_name(unsigned char type)
{
    switch (type) {
#define F(type) case type: return #type
        F(DT_BLK);
        F(DT_CHR);
        F(DT_DIR);
        F(DT_FIFO);
        F(DT_LNK);
        F(DT_REG);
        F(DT_SOCK);
        default: return "DT_UNKNOWN";
#undef F
    }
}
#endif

static const struct finfo_op available_ops[] = {
    { "stat",     FINFO_OP_ENABLED,  finfo_stat },
    { "lstat",    FINFO_OP_DISABLED, finfo_lstat },
    { "readlink", FINFO_OP_DISABLED, finfo_readlink },
    { "ls",       FINFO_OP_DISABLED, finfo_ls },
    { "sha256",   FINFO_OP_DISABLED, finfo_sha256 },
    { "execp",    FINFO_OP_DISABLED, finfo_execp },
};

#define NOPS ARRAYSIZE(available_ops)

static void
finfo_ls(struct json_writer* writer, const char* filename, void* data)
{
    struct cleanup* cl = cleanup_allocate();
    DIR* dir = opendir(filename);
    if (dir == NULL)
        die_errno("opendir");
    cleanup_commit(cl, cleanup_closedir, dir);

    json_begin_array(writer);

    struct dirent* ent;
    while ((errno = 0, (ent = readdir(dir))) != NULL) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
            continue;

        enum {
            ENT_TYPE_UNKNOWN,
            ENT_TYPE_DIR,
            ENT_TYPE_NONDIR,
        } ent_type = ENT_TYPE_UNKNOWN;

        SCOPED_RESLIST(rl_ent);
        json_begin_object(writer);
        json_begin_field(writer, "d_name");
        json_emit_string(writer, ent->d_name);
        json_begin_field(writer, "d_ino");
        json_emit_u64(writer, (uint64_t) ent->d_ino);

#ifdef HAVE_STRUCT_DIRENT_D_TYPE
        json_begin_field(writer, "d_type");
        json_emit_string(writer, dirent_type_to_name(ent->d_type));
        if (ent->d_type != DT_UNKNOWN)
            ent_type = (ent->d_type == DT_DIR) ? ENT_TYPE_DIR : ENT_TYPE_NONDIR;
#endif

        const char* fullname = xaprintf("%s/%s", filename, ent->d_name);
        const struct finfo_op* subops = data;
        for (unsigned i = 0; i < NOPS; ++i) {
            if (subops[i].state != FINFO_OP_DISABLED) {
                if (subops[i].fn == finfo_ls) {
                    if (ent_type == ENT_TYPE_UNKNOWN) {
                        struct stat st;
                        if (stat(fullname, &st) == 0)
                            ent_type = S_ISDIR(st.st_mode)
                                ? ENT_TYPE_DIR
                                : ENT_TYPE_NONDIR;
                    }
                    
                    if (ent_type == ENT_TYPE_NONDIR)
                        continue;
                }

                json_begin_field(writer, subops[i].name);
                emit_finfo_op(writer,
                              fullname,
                              subops[i].fn,
                              subops[i].fndata);
            }
        }

        json_end_object(writer);
    }

    if (errno != 0)
        die_errno("readdir");

    json_end_array(writer);
}

struct emit_finfo_context {
    struct json_writer* writer;
    const char* filename;
    finfo_op_fn fn;
    void* fndata;
};

static void
emit_finfo_op_1(void* data)
{
    struct emit_finfo_context* ctx = data;
    ctx->fn(ctx->writer, ctx->filename, ctx->fndata);
}

static void
emit_finfo_op(
    struct json_writer* writer,
    const char* filename,
    finfo_op_fn fn,
    void* fndata)
{
    SCOPED_RESLIST(rl);

    struct emit_finfo_context ctx = {
        .writer = writer,
        .filename = filename,
        .fn = fn,
        .fndata = fndata,
    };

    json_begin_object(writer);
    const struct json_context* saved_context = json_save_context(writer);

    json_begin_field(writer, "result");
    struct errinfo ei = {
        .want_msg = true,
    };

    bool failed = catch_error(emit_finfo_op_1, &ctx, &ei);
    json_pop_to_saved_context(writer, saved_context);
    if (failed) {
        json_begin_field(writer, "error");
        json_begin_object(writer);
        json_begin_field(writer, "errno");
        json_emit_i64(writer, ei.err);
        json_begin_field(writer, "errmsg");
        json_emit_string(writer, ei.msg);
        json_end_object(writer);
    } else {
        assert(json_save_context(writer) == saved_context);
    }
    json_end_object(writer);
}

#define PARSE_OPLIST_ALLOW_SUBOPTIONS (1<<0)
#define PARSE_OPLIST_NO_DEFAULTS (1<<1)

static struct finfo_op*
parse_oplist(const char* spec,
             const char* delim,
             unsigned flags,
             bool* want_recursion)
{
    struct finfo_op* ops = xalloc(sizeof (available_ops));
    memcpy(ops, available_ops, sizeof (available_ops));
    for (unsigned i = 0; i < NOPS; ++i)
        ops[i].state = FINFO_OP_DISABLED;

    if (want_recursion)
        *want_recursion = false;

    char* opstr = xstrdup(spec);
    char* saveptr = NULL;
    char* opname;
    for (opname = strtok_r(opstr, delim, &saveptr);
         opname != NULL;
         opname = strtok_r(NULL, delim, &saveptr))
    {
        if (want_recursion && !strcmp(opname, "recursive")) {
            *want_recursion = true;
            opname = "ls";
        }

        char* subopts = NULL;
        char* colon = strchr(opname, ':');
        if (colon != NULL) {
            subopts = colon+1;
            *colon = '\0';
        }

        unsigned i;
        for (i = 0; i < NOPS; ++i)
            if (!strcmp(ops[i].name, opname))
                break;

        if (i == NOPS)
            die(EINVAL, "unknown operation %s", opname);

        ops[i].state = FINFO_OP_ENABLED;

        if (subopts && (flags & PARSE_OPLIST_ALLOW_SUBOPTIONS) == 0)
            die(EINVAL, "sub-options cannot have sub-options");

        if (ops[i].fn != finfo_ls) {
            if (subopts)
                die(EINVAL, "operation %s not accept options", opname);
        } else {
            bool want_recursion;
            struct finfo_op* lsops = parse_oplist(
                subopts ?: "",
                "+",
                0,
                &want_recursion);
            ops[i].fndata = lsops;
            if (want_recursion) {
                for (unsigned i = 0; i < NOPS; ++i) {
                    if (lsops[i].fn == finfo_ls) {
                        lsops[i].fndata = lsops;
                        break;
                    }
                }
            }
        }
    }

    return ops;
}

int
finfo_main(const struct cmd_finfo_info* info)
{
    const struct finfo_op* ops = available_ops;
    if (info->finfo.info) {
        ops = parse_oplist(
            info->finfo.info,
            ",",
            PARSE_OPLIST_ALLOW_SUBOPTIONS,
            NULL);
    }

    struct json_writer* writer = json_writer_create(stdout);
    json_begin_array(writer);
    for (const char* const* paths = info->paths; *paths; ++paths) {
        const char* path = *paths;
        json_begin_object(writer);
        json_begin_field(writer, "filename");
        json_emit_string(writer, path);
        for (unsigned i = 0; i < NOPS; ++i) {
            if (ops[i].state != FINFO_OP_DISABLED) {
                json_begin_field(writer, ops[i].name);
                emit_finfo_op(writer, path, ops[i].fn, ops[i].fndata);
            }
        }
        json_end_object(writer);
    }
    json_end_array(writer);

    if (fflush(stdout) == EOF)
        die_errno("fflush");

    return 0;
}

#endif

