#include <termios.h>
#include <errno.h>
#include "xmkraw.h"
#include "util.h"

struct xmkraw_save {
    int fd;
    struct termios attr;
};

void
xtcgetattr(int fd, struct termios* attr)
{
    int ret;

    do {
        ret = tcgetattr(fd, attr);
    } while (ret == -1 && errno == EINTR);

    if (ret < 0)
        die_errno("tcgetattr(%d)", fd);
}

void
xtcsetattr(int fd, struct termios* attr)
{
    int ret;

    do {
        ret = tcsetattr(fd, TCSADRAIN, attr);
    } while (ret == -1 && errno == EINTR);

    if (ret < 0)
        die_errno("tcsetattr(%d)", fd);
}

static void
xmkraw_cleanup(void* arg)
{
    struct xmkraw_save* save = arg;
    int ret;
    do {
        ret = tcsetattr(save->fd, TCSADRAIN, &save->attr);
    } while (ret == -1 && errno == EINTR);
    close(save->fd);
}

void
xmkraw(int fd)
{
    struct xmkraw_save* save = xalloc(sizeof (*save));
    struct termios attr;
    xtcgetattr(fd, &attr);
    struct cleanup* cl = cleanup_allocate();
    save->fd = dup(fd);
    if (save->fd == -1)
        die_errno("dup");
    save->attr = attr;
    cleanup_commit(cl, xmkraw_cleanup, save);

    cfmakeraw(&attr);
    xtcsetattr(fd, &attr);
}
