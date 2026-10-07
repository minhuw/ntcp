// libc owns buffering, formatting, FILE locks and destruction. We only supply
// socket transport callbacks and the identity libc's cookie streams lack.
#define _GNU_SOURCE
#include "boundary.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
extern int ntcp_boundary_fd(int);
extern uint64_t ntcp_stdio_id(int);
extern int ntcp_stdio_valid(int, uint64_t);
extern ssize_t ntcp_managed_read(int, void *, size_t);
extern ssize_t ntcp_managed_write(int, const void *, size_t);
extern int ntcp_managed_close(int);

// ponytail: at most 512 live managed FILEs; raise alongside the socket limit.
struct cookie {
    _Atomic int used;
    _Atomic(FILE *) stream;
    int fd;
    uint64_t id;
};
static struct cookie cookies[512];
static FILE *(*_Atomic real_fdopen)(int, const char *);
static int (*_Atomic real_fileno)(FILE *);
static int (*_Atomic real_fileno_unlocked)(FILE *);
static FILE *(*_Atomic real_cookie)(void *, const char *, cookie_io_functions_t);
static _Atomic int initialized;
static _Thread_local int resolving;
__attribute__((constructor)) static void resolve_stdio(void) {
    resolving = 1;
    real_fdopen = dlsym(RTLD_NEXT, "fdopen");
    real_fileno = dlsym(RTLD_NEXT, "fileno");
    real_fileno_unlocked = dlsym(RTLD_NEXT, "fileno_unlocked");
    real_cookie = dlsym(RTLD_NEXT, "fopencookie");
    resolving = 0;
    atomic_store(&initialized, 1);
}
static void ensure_stdio(void) {
    if (!atomic_load(&initialized) && !resolving) resolve_stdio();
}
static ssize_t cookie_read(void *p, char *buf, size_t n) {
    struct cookie *c = p;
    int state;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
    ssize_t result = ntcp_stdio_valid(c->fd, c->id) < 0 ? -1 : ntcp_managed_read(c->fd, buf, n);
    int saved = errno;
    pthread_setcancelstate(state, NULL);
    errno = saved;
    return result;
}
static ssize_t cookie_write(void *p, const char *buf, size_t n) {
    struct cookie *c = p;
    int state;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
    ssize_t result = 0;
    while ((size_t)result < n) {
        ssize_t sent = ntcp_stdio_valid(c->fd, c->id) < 0 ? -1 :
            ntcp_managed_write(c->fd, buf + result, n - (size_t)result);
        if (sent <= 0) break;
        result += sent;
    }
    int saved = errno;
    pthread_setcancelstate(state, NULL);
    errno = saved;
    // fopencookie requires zero, not -1, on a write error.
    return result;
}
static int cookie_seek(void *p, off64_t *offset, int whence) {
    (void)p; (void)offset; (void)whence;
    errno = ESPIPE;
    return -1;
}
static int cookie_close(void *p) {
    struct cookie *c = p;
    int state;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
    int result = ntcp_stdio_valid(c->fd, c->id) < 0 ? -1 : ntcp_managed_close(c->fd);
    int saved = errno;
    atomic_store(&c->stream, NULL);
    atomic_store(&c->used, 0);
    pthread_setcancelstate(state, NULL);
    errno = saved;
    return result;
}
FILE *ntcp_c_fdopen(int fd, const char *mode) {
    ensure_stdio();
    if (!real_fdopen) { errno = ENOSYS; return NULL; }
    if (!NTCP_RUST_CALL(int, ntcp_boundary_fd(fd))) return real_fdopen(fd, mode);
    int state;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
    FILE *result = NULL;
    struct cookie *c = NULL;
    uint64_t id = ntcp_stdio_id(fd);
    if (!id) goto done;
    if (!mode || (mode[0] != 'r' && mode[0] != 'w' && mode[0] != 'a')) {
        errno = EINVAL;
        goto done;
    }
    // Match fdopen's access validation; a socket is normally O_RDWR.
    int flags = syscall(SYS_fcntl, fd, F_GETFL, 0);
    if (flags < 0) goto done;
    int access = mode[0] == 'r' ? O_RDONLY : O_WRONLY;
    for (const char *p = mode + 1; *p; ++p) if (*p == '+') access = O_RDWR;
    if ((flags & O_ACCMODE) != O_RDWR && (flags & O_ACCMODE) != access) {
        errno = EINVAL;
        goto done;
    }
    if (mode[0] == 'a' && !(flags & O_APPEND) &&
        syscall(SYS_fcntl, fd, F_SETFL, flags | O_APPEND) < 0) goto done;
    for (size_t i = 0; i < sizeof(cookies) / sizeof(cookies[0]); ++i) {
        int unused = 0;
        if (atomic_compare_exchange_strong(&cookies[i].used, &unused, 1)) {
            c = &cookies[i];
            break;
        }
    }
    if (!c) { errno = EMFILE; goto done; }
    c->fd = fd;
    c->id = id;
    cookie_io_functions_t io = {cookie_read, cookie_write, cookie_seek, cookie_close};
    // Append has no positioning effect on a socket. Avoid libc cookie's
    // automatic seek-to-end, which would incorrectly reject it with ESPIPE.
    result = real_cookie(c, mode[0] == 'a' ? (access == O_RDWR ? "w+" : "w") : mode, io);
    if (result) atomic_store(&c->stream, result);
    else atomic_store(&c->used, 0); // Failed fdopen never takes descriptor ownership.
done:;
    int saved = errno;
    pthread_setcancelstate(state, NULL);
    errno = saved;
    return result;
}
static int cookie_fileno(FILE *stream, int unlocked) {
    ensure_stdio();
    if (!real_fileno || !real_fileno_unlocked) { errno = ENOSYS; return -1; }
    for (size_t i = 0; i < sizeof(cookies) / sizeof(cookies[0]); ++i)
        if (stream && atomic_load(&cookies[i].stream) == stream) return cookies[i].fd;
    return unlocked ? real_fileno_unlocked(stream) : real_fileno(stream);
}
int ntcp_c_fileno(FILE *stream) { return cookie_fileno(stream, 0); }
int ntcp_c_fileno_unlocked(FILE *stream) { return cookie_fileno(stream, 1); }
