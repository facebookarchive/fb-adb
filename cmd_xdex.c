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
#include <limits.h>
#include "util.h"
#include "autocmd.h"
#include "constants.h"
#include "fs.h"
#include "xfer.h"
#include "child.h"
#include "peer.h"
#include "dex.h"

#if FBADB_MAIN

#include "agent.h"

static const char* const xdex_path_suffixes[] = {"", ".dex", ".dex.jar" };

static int
search_xdex_path(
    const char* base,
    const char** found_program,
    const char* path)
{
    SCOPED_RESLIST(rl);
    char* saveptr = NULL;
    for (const char* path_ent = strtok_r(xstrdup(path), ":", &saveptr);
         path_ent != NULL;
         path_ent = strtok_r(NULL, ":", &saveptr))
    {
        SCOPED_RESLIST(rl_each_path);
        for (size_t i = 0; i < ARRAYSIZE(xdex_path_suffixes); ++i) {
            const char* suffix = xdex_path_suffixes[i];
            const char* candidate =
                xaprintf("%s/%s%s", path_ent, base, suffix);
            int fd = try_xopen(candidate, O_RDONLY, 0);
            if (fd != -1) {
                WITH_CURRENT_RESLIST(rl->parent);
                *found_program = xstrdup(candidate);
                return xdup(fd);
            }
        }
    }

    die(ENOENT, "could not find dex program `%s' on path", base);
}

enum dex_format {
    DEX_FORMAT_UNKNOWN,
    DEX_FORMAT_DEX,
    DEX_FORMAT_DEX_JAR,
};

static enum dex_format
check_dex_format(int fd)
{
    char hdr[4];
    size_t hdrsz = read_all(fd, hdr, sizeof (hdr));
    if (hdrsz == 4) {
        if (memcmp(hdr, "PK\x03\x04", 4) == 0)
            return DEX_FORMAT_DEX_JAR; // Any zip .dex.jar? Close enough.
        if (memcmp(hdr, "\x64\x65\x78\0a", 4) == 0)
            return DEX_FORMAT_DEX;
    }
    return DEX_FORMAT_UNKNOWN;
}

static char*
run_xdex_stub(const struct adb_opts* adb,
              const struct transport_opts* transport,
              const struct user_opts* user,
              const char* name)
{
    SCOPED_RESLIST(rl);
    struct start_peer_info spi = {
        // Not cwd: we want default in case we have a package
        .adb = *adb,
        .transport = *transport,
        .user = *user,
        .specified_io = true,
        .io[STDIN_FILENO] = CHILD_IO_DEV_NULL,
        .io[STDOUT_FILENO] = CHILD_IO_PIPE,
    };

    struct cmd_xdex_stub_info stub_args = {
        .name = name,
    };

    struct child* peer = start_peer(
        &spi,
        make_args_cmd_xdex_stub(
            CMD_ARG_NAME | CMD_ARG_ALL,
            &stub_args));
    char* resp = slurp_fd(peer->fd[STDOUT_FILENO]->fd, NULL);
    child_wait_die_on_error(peer);
    WITH_CURRENT_RESLIST(rl->parent);
    return xstrdup(resp);
}

int
xdex_main(const struct cmd_xdex_info* info)
{
    if (info->program[0] == '\0')
        usage_error("PROGRAM option to xdex cannot be empty");

    if (info->shex.exename)
        usage_error("--exename makes no sense with xdex");

    int program_fd;
    const char* found_program;
    if (strchr(info->program, '/') != NULL) {
        program_fd = xopen(info->program, O_RDONLY, 0);
        found_program = info->program;
    } else {
        program_fd = search_xdex_path(
            info->program,
            &found_program,
            getenv("FB_ADB_XDEX_PATH") ?: ".");
    }

    switch (check_dex_format(program_fd)) {
        default:
            abort();
        case DEX_FORMAT_UNKNOWN:
            die(EINVAL,
                "dex program `%s' has unknown format",
                found_program);
        case DEX_FORMAT_DEX:
            die(EINVAL,
                "dex program `%s' must be a jar file, not raw dex",
                found_program);
        case DEX_FORMAT_DEX_JAR:
            break;
    }

    xrewindfd(program_fd);
    struct sha256_hash program_hash = sha256_fd(program_fd);
    char* found_program_basename = xbasename(found_program);
    char* dot = strchr(found_program_basename, '.');
    if (dot != NULL)
        *dot = '\0';
    if (found_program_basename[0] == '\0')
        die(EINVAL, "empty xdex basename");

    char* name = xaprintf(
        "%s-%s",
        found_program_basename,
        hex_encode_bytes(
        program_hash.digest,
        sizeof (program_hash.digest) / 2));
    char* resp = run_xdex_stub(
        &info->adb,
        &info->transport,
        &info->user,
        name);
    dbg("resp from xdex stub: [%s]", resp);
    char status = *resp++;
    if (status != 'Y' && status != 'N')
        die(ECOMM, "invalid stub response code %d", (int) status);
    char* full_dex_jar_path = resp;
    if (status == 'N') {
        xrewindfd(program_fd);
        send_file_to_device(
            &info->adb,
            &info->transport,
            &info->user,
            program_fd,
            full_dex_jar_path,
            0600);
        resp = run_xdex_stub(
            &info->adb,
            &info->transport,
            &info->user,
            name);
        if (*resp++ != 'Y')
            die(EINVAL, "dex state not acceptable after upload");
        full_dex_jar_path = resp;
    }

    set_prgname("rdex");
    struct cmd_rdex_info rdex_info = {
        .rdex.no_compile = 1,
        .adb = info->adb,
        .transport = info->transport,
        .user = info->user,
        .cwd = info->cwd,
        .shex = info->shex,
        .dexfile = full_dex_jar_path,
        .classname = info->classname,
        .args = info->args,
    };

    return rdex_main(&rdex_info);
}

int
agent_main(const struct cmd_agent_info* info)
{
    char* resp = run_xdex_stub(
        &info->adb,
        &info->transport,
        &info->user,
        agent_name);
    char status = *resp++;
    char* full_dex_jar_path = resp;
    if (status != 'Y' && status != 'N')
        die(ECOMM, "invalid stub response code %d", (int) status);
    if (status == 'N') {
        SCOPED_RESLIST(send_rl);
        const char* program_tmpname;
        int program_fd = xnamed_tempfile(&program_tmpname);
        write_all(program_fd, agent_dex_jar, agent_dex_jar_size);
        xrewindfd(program_fd);
        send_file_to_device(
            &info->adb,
            &info->transport,
            &info->user,
            program_fd,
            full_dex_jar_path,
            0600);
        resp = run_xdex_stub(
            &info->adb,
            &info->transport,
            &info->user,
            agent_name);
        if (*resp++ != 'Y')
            die(EINVAL, "dex state not acceptable after upload");
        WITH_CURRENT_RESLIST(send_rl->parent);
        full_dex_jar_path = xstrdup(resp);
    }

    set_prgname("rdex");
    struct cmd_rdex_info rdex_info = {
        .rdex.no_compile = 1,
        .adb = info->adb,
        .transport = info->transport,
        .user = info->user,
        .dexfile = full_dex_jar_path,
        .classname = "com.facebook.fbadb.agent.Agent",
        .args = info->args,
    };
    return rdex_main(&rdex_info);
}

#else // !FBADB_MAIN below

int
xdex_stub_main(const struct cmd_xdex_stub_info* info) {
    set_prgname("");
    const char* name = info->name;
    const char* dex_jar_name = xaprintf("xdex-%s.dex.jar", name);
    const char* mydir = my_fb_adb_directory();
    const char* dex_jar_fullname = xaprintf("%s/%s", mydir, dex_jar_name);

    char status = 'N';
    if (access(dex_jar_fullname, F_OK) == 0) {
        compile_dex(dex_jar_fullname);
        status = 'Y';
    }

    xprintf(xstdout, "%c", status);
    xprintf(xstdout, "%s", dex_jar_fullname);
    xflush(xstdout);
    return 0;
}

#endif
