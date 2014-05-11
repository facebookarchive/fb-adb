#include <stdlib.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <sys/wait.h>
#include "adb.h"
#include "child.h"
#include "util.h"

void
adb_send_file(const char* local, const char* remote)
{
    SCOPED_RESLIST(rl_send_stub);
    struct child_start_info csi = {
        .flags = CHILD_MERGE_STDERR,
        .exename = "adb",
        .argv = (const char*[]){"adb", "push", local, remote, NULL},
    };
    struct child* adb = child_start(&csi);
    fdh_destroy(adb->fd[0]);

    char buf[512];
    size_t len = read_all(adb->fd[1]->fd, buf, sizeof (buf));
    fdh_destroy(adb->fd[1]);

    int status = xwaitpid(adb->pid);
    if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
        if (len == sizeof (buf))
            --len;

        while (len > 0 && isspace(buf[len - 1]))
            --len;

        buf[len] = '\0';

        char* epos = buf;
        while (*epos != '\0' && isspace(*epos))
            ++epos;

        die(ECOMM, "adb error: %s", epos);
    }
}
