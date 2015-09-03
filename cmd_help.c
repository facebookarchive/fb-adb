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

int
help_main(const struct cmd_help_info* info)
{
    if (info->for_command) {
        const struct cmd* cmd = &autocmds[0];
        while (cmd->main != NULL) {
            if (!strcmp(cmd->name, info->for_command))
                break;
            cmd++;
        }

        if (cmd->main == NULL)
            die(EINVAL, "no command \"%s\"", info->for_command);

        execl(orig_argv0, orig_argv0, info->for_command, "--help", NULL);
        die_errno("execl");
    } else {
        show_help(full_usage);
    }

    return 0;
}
