#pragma once
struct termios;
void xtcgetattr(int fd, struct termios* attr);
void xtcsetattr(int fd, struct termios* attr);
#define XMKRAW_SKIP_CLEANUP 0x1
void xmkraw(int fd, unsigned flags);
