#define _GNU_SOURCE
#include <stdarg.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
extern int ntcp_fcntl_dispatch(int, int, unsigned long);
extern int ntcp_ioctl_dispatch(int, unsigned long, unsigned long);
int ntcp_variadic_fcntl(int fd, int cmd, ...) {
    unsigned long arg = 0;
    va_list ap;
    va_start(ap, cmd);
    switch (cmd) {
    case F_GETFD: case F_GETFL: case F_GETOWN: case F_GETSIG:
    case F_GETLEASE: case F_GETPIPE_SZ: case F_GET_SEALS: break;
    case F_DUPFD: case F_DUPFD_CLOEXEC: case F_SETFD: case F_SETFL:
    case F_SETOWN: case F_SETSIG: case F_SETLEASE: case F_NOTIFY:
    case F_SETPIPE_SZ: case F_ADD_SEALS: arg = (unsigned long)va_arg(ap, int); break;
    default: arg = (unsigned long)va_arg(ap, void *); break;
    }
    va_end(ap);
    return ntcp_fcntl_dispatch(fd, cmd, arg);
}
int ntcp_variadic_ioctl(int fd, unsigned long cmd, ...) {
    unsigned long arg = 0;
    va_list ap;
    va_start(ap, cmd);
    /* Linux's no-argument tty requests must not read absent varargs. */
    if (cmd != FIOCLEX && cmd != FIONCLEX && cmd != TIOCEXCL && cmd != TIOCNXCL
        && cmd != TIOCNOTTY && cmd != TIOCSBRK && cmd != TIOCCBRK && cmd != TIOCVHANGUP) {
        if (cmd == TCSBRK || cmd == TCXONC || cmd == TCFLSH || cmd == TCSBRKP || cmd == TIOCSCTTY)
            arg = (unsigned long)va_arg(ap, int);
        else
            arg = (unsigned long)va_arg(ap, void *);
    }
    va_end(ap);
    return ntcp_ioctl_dispatch(fd, cmd, arg);
}
