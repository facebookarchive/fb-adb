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

#ifdef USE_NCURSES
# include <curses.h>
# include <term.h>
#endif

#include <stdarg.h>
#include <stdlib.h>
#include "util.h"
#include "cmd.h"
#include "autocmd.h"
#include "strutil.h"
#include "fs.h"

void
usage_error(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    diev(EINVAL, fmt, args);
}

void
append_argv_accumulation(struct strlist* sl,
                         const struct strlist* accum)
{
    SCOPED_RESLIST(rl);
    for (const char* s = strlist_rewind(accum);
         s != NULL;
         s = strlist_next(accum))
    {
        strlist_append(sl, xaprintf("--%s", s));
    }
}

void
accumulate_option(struct strlist** slp,
                  const char* opt,
                  const char* val)
{
    SCOPED_RESLIST(rl);
    struct strlist* sl = *slp;
    if (sl == NULL)
        sl = *slp = strlist_new();

    strlist_append(sl, val ? xaprintf("%s=%s", opt, val) : opt);
}

static bool
long_opt_p(const char* opt)
{
    return opt[0] == '-' && opt[1] == '-' && opt[2] != '\0';
}

struct caps {
    char* sgr0;
    char* bold;
    char* smul;
    char* setaf;
};

#ifdef USE_NCURSES
static FILE* ansi_out;
static int
putc_translate_ansi_out(int c) {
    return putc(c, ansi_out);
}
#endif

static void
set_ansi_mode(FILE* out, unsigned mode, const struct caps* caps)
{
#ifdef USE_NCURSES
    if (caps) {
        char* emit = NULL;
        if (mode == 0) {
            emit = caps->sgr0;
        } else if (mode == 1) {
            emit = caps->bold;
        } else if (mode >= 30) {
            if (caps->setaf)
                emit = tiparm(caps->setaf, (int) mode - 30);
            else if (caps->smul)
                emit = caps->smul;
        }

        if (emit != NULL) {
            ansi_out = out;
            tputs(emit, 1, putc_translate_ansi_out);
        }
    }
#endif
}

static void
fputs_translate_ansi(FILE* out, const char* text, bool use_ansi)
{
    const struct caps* pcaps = NULL;
#ifdef USE_NCURSES
    struct caps caps = { 0 };
    bool setupterm_success = false;
    if (use_ansi)
        setupterm_success = (setupterm(NULL, fileno(out), NULL) == OK);
    if (setupterm_success) {
        caps.sgr0 = tigetstr("sgr0");
        caps.bold = tigetstr("bold");
        caps.smul = tigetstr("smul");
        caps.setaf = tigetstr("setaf");
        if (caps.sgr0)
            pcaps = &caps;
    }
#endif

    unsigned arg = 0;

    enum {
        NORMAL,
        AFTER_ESC,
        AFTER_CSI,
    } state = NORMAL;

    char c;
    while ((c = *text++) != '\0') {
        switch (state) {
            case NORMAL:
                if (c == '\033') {
                    state = AFTER_ESC;
                } else {
                    putc(c, out);
                }
                break;
            case AFTER_ESC:
                if (c == '[') {
                    state = AFTER_CSI;
                    arg = 0;
                } else {
                    state = NORMAL;
                }
                break;
            case AFTER_CSI:
                if ('0' <= c && c <= '9') {
                    arg = arg * 10 + (c - '0');
                } else if (c == 'm') {
                    set_ansi_mode(out, arg, pcaps);
                    state = NORMAL;
                } else {
                    state = NORMAL;
                }
                break;
        }
    }

#ifdef USE_NCURSES
    if (setupterm_success)
        reset_shell_mode();
#endif
}

static void
show_help_1(const char* help, bool allow_pager)
{
    SCOPED_RESLIST(rl);
    FILE* out = stdout;
    int color_override = -1;
    if (getenv("FB_ADB_COLOR")) {
        color_override = atoi(getenv("FB_ADB_COLOR"));
    }

    const char* pager = NULL;
    bool pager_supports_color = false;

    if (allow_pager) {
        pager = getenv("PAGER") ?: "less";
        if (!strcmp(pager, "less") ||
            string_starts_with_p(pager, "less "))
        {
            pager = xaprintf("%s -R", pager);
            pager_supports_color = true;
        }
    }

    if (pager != NULL && *pager == '\0')
        pager = NULL;

    const char* tmpf_name = NULL;
    if (pager != NULL) {
        out = xnamed_tempfile(&tmpf_name);
    }

    if (color_override == -1)
        color_override = pager_supports_color || isatty(fileno(out));

    fputs_translate_ansi(out, help, color_override > 0);
    fflush(out);
    if (tmpf_name) {
        if (system(xaprintf("%s %s", pager, xshellquote(tmpf_name))) != 0)
            show_help_1(help, false);
    }
}

void
show_help(const char* help)
{
    show_help_1(help, isatty(0) && isatty(1));
}

void
default_getopt(char c, const char* const* argv, const char* usage)
{
    switch (c) {
        case ':':
            if (optopt == '\0' || long_opt_p(argv[optind-1])) {
                usage_error("missing argument for %s", argv[optind-1]);
            } else {
                usage_error("missing argument for -%c", optopt);
            }
        case '?':
            if (optopt == '?' ||
                optopt == 'h' ||
                (optopt == '\0' && !strcmp(argv[optind-1], "--help")))
            {
                if (usage == NULL)
                    die(EINVAL, "incorrect usage of internal command");
                show_help(usage);
                exit(0);
            } else if (optopt == '\0' || long_opt_p(argv[optind-1])) {
                usage_error("invalid option %s", argv[optind-1]);
            } else {
                usage_error("invalid option -%c", (int) optopt);
            }
        default:
            abort();

    }
}

#if FBADB_MAIN
int
forward_to_rcmd(struct strlist* non_forwarded_args,
                struct strlist* forwarded_args)
{
    struct strlist* sl = strlist_new();
    strlist_append(sl, prgname);
    strlist_xfer(sl, non_forwarded_args);
    strlist_append(sl, "-E/proc/self/exe");
    strlist_append(sl, "--");
    strlist_append(sl, 1+(strrchr(orig_argv0, '/') ?: orig_argv0-1));
    strlist_append(sl, 1+(strrchr(prgname, ' ') ?: prgname-1));
    strlist_xfer(sl, forwarded_args);
    struct cmd_rcmd_info rinfo;
    memset(&rinfo, 0, sizeof (rinfo));
    const char** argv = strlist_to_argv(sl);
    parse_args_cmd_rcmd(&rinfo, argv_count(argv), argv);
    return rcmd_main(&rinfo);
}
#endif
