#pragma once
struct termios;
void xtcgetattr(int fd, struct termios* attr);
void xtcsetattr(int fd, struct termios* attr);
void xmkraw(int fd);
