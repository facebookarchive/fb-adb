#include <termios.h>
#include "xmkraw.h"
#include "util.h"

struct xmkraw_save {
    int fd;
    struct termios attr;
};

static void
xmkraw_cleanup(void* arg)
{
    struct xmkraw_save* save = arg;
    tcsetattr(save->fd, TCSADRAIN, &save->attr);
}

void
xmkraw(int fd)
{
    struct xmkraw_save* save = xalloc(sizeof (*save));
    struct cleanup* cl = cleanup_allocate();
    struct termios attr;
    if (tcgetattr(fd, &attr) < 0)
        die_errno("tcgetattr(%d)", fd);

    save->fd = fd;
    save->attr = attr;
    cleanup_commit(cl, xmkraw_cleanup, save);
    cfmakeraw(&attr);
    if (tcsetattr(fd, TCSADRAIN, &attr) < 0)
        die_errno("tcsetattr(%d)", fd);
}
