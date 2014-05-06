#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include "util.h"

extern int stub_main(int, char**);
extern int shex_main(int, char**);

int
real_main(int argc, char** argv)
{
    if (argc < 2)
        die(EINVAL, "no sub-command given");

    int (*sub_main)(int, char**) = NULL;
    if (!strcmp(argv[1], "stub"))
        sub_main = stub_main;
    else if (!strcmp(argv[1], "shex"))
        sub_main = shex_main;

    if (sub_main) {
        argv[1] = prgname = xaprintf("%s %s", argv[0], argv[1]);
        return sub_main(argc - 1, argv + 1);
    }

    die(EINVAL, "unknown sub-command %s", argv[1]);
}
