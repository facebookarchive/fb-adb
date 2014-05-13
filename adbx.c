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

__attribute__((noreturn))
static void
usage(void)
{
    printf("adbx %s - ADB wrapper\n", PACKAGE_VERSION);
    printf("\n");
    printf("  adbx {sh,shex} [CMD ARGS...] - Improved adb shell.\n");
    printf("\n");
    printf("  Unrecognized commands forward to adb\n");
    printf("\n");
    fflush(stdout);
            
    /* adb help normally writes to stderr, so redirect to
     * stdout for sanity. */
    dup2(1, 2);
    
    execlp("adb", "help", NULL);
    die(EINVAL, "could not exec adb: %s", strerror(errno));
}

int
real_main(int argc, char** argv)
{
    int (*sub_main)(int, char**) = NULL;

    if (!strcmp(prgname, "adsh"))
        return shex_main(argc, argv);

    if (argc < 2)
        die(EINVAL, "no sub-command given. Use --help for help.");

    if (sub_main == NULL && !strcmp(argv[1], "stub"))
        sub_main = stub_main;

    if (sub_main == NULL && (!strcmp(argv[1], "shex") ||
                             !strcmp(argv[1], "sh")))
        sub_main = shex_main;

    if (sub_main == NULL) {
        if (!strcmp(argv[1], "help") ||
            !strcmp(argv[1], "--help"))
        {
            usage();
        }

        execvp("adb", argv);
        die(EINVAL, "could not exec adb: %s", strerror(errno));
    }

    argv[1] = xaprintf("%s %s", prgname, argv[1]);
    set_prgname(argv[1]);
    return sub_main(argc - 1, argv + 1);
}
