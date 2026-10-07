// Native cancellation points live entirely in C: POSIX forced unwind must
// never cross a Rust frame. Internal runtime operations still use raw syscalls.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <poll.h>
#include <unistd.h>
// Managed blocking cancellation remains deferred until a future safe C wait
// boundary exists. Mask it throughout Rust, including runtime bootstrap.
// Initial-exec TLS cannot allocate or take loader locks in a signal handler.
static _Thread_local int internal __attribute__((tls_model("initial-exec")));
void ntcp_set_internal(int value) { internal = value; }
extern int ntcp_boundary_socket(int, int);
extern int ntcp_managed_socket(int, int, int);
static int (*_Atomic real_socket)(int, int, int);
extern int ntcp_boundary_fd(int);
extern int ntcp_boundary_epoll(int);
extern int ntcp_boundary_poll(const struct pollfd *, nfds_t);
extern int ntcp_boundary_select(int, const fd_set *, const fd_set *, const fd_set *);
extern ssize_t ntcp_managed_read(int fd, void *p, size_t n);
static ssize_t (*_Atomic real_read)(int fd, void *p, size_t n);
extern ssize_t ntcp_managed_write(int fd, const void *p, size_t n);
static ssize_t (*_Atomic real_write)(int fd, const void *p, size_t n);
extern ssize_t ntcp_managed_readv(int fd, const struct iovec *v, int n);
static ssize_t (*_Atomic real_readv)(int fd, const struct iovec *v, int n);
extern ssize_t ntcp_managed_writev(int fd, const struct iovec *v, int n);
static ssize_t (*_Atomic real_writev)(int fd, const struct iovec *v, int n);
extern ssize_t ntcp_managed_send(int fd, const void *p, size_t n, int flags);
static ssize_t (*_Atomic real_send)(int fd, const void *p, size_t n, int flags);
extern ssize_t ntcp_managed_recv(int fd, void *p, size_t n, int flags);
static ssize_t (*_Atomic real_recv)(int fd, void *p, size_t n, int flags);
extern ssize_t ntcp_managed_sendto(int fd, const void *p, size_t n, int flags, const struct sockaddr *addr, socklen_t len);
static ssize_t (*_Atomic real_sendto)(int fd, const void *p, size_t n, int flags, const struct sockaddr *addr, socklen_t len);
extern ssize_t ntcp_managed_recvfrom(int fd, void *p, size_t n, int flags, struct sockaddr *addr, socklen_t *len);
static ssize_t (*_Atomic real_recvfrom)(int fd, void *p, size_t n, int flags, struct sockaddr *addr, socklen_t *len);
extern ssize_t ntcp_managed_sendmsg(int fd, const struct msghdr *p, int flags);
static ssize_t (*_Atomic real_sendmsg)(int fd, const struct msghdr *p, int flags);
extern ssize_t ntcp_managed_recvmsg(int fd, struct msghdr *p, int flags);
static ssize_t (*_Atomic real_recvmsg)(int fd, struct msghdr *p, int flags);
extern int ntcp_managed_accept(int fd, struct sockaddr *p, socklen_t *len);
static int (*_Atomic real_accept)(int fd, struct sockaddr *p, socklen_t *len);
extern int ntcp_managed_accept4(int fd, struct sockaddr *p, socklen_t *len, int flags);
static int (*_Atomic real_accept4)(int fd, struct sockaddr *p, socklen_t *len, int flags);
extern int ntcp_managed_connect(int fd, const struct sockaddr *p, socklen_t len);
static int (*_Atomic real_connect)(int fd, const struct sockaddr *p, socklen_t len);
extern int ntcp_managed_close(int fd);
static int (*_Atomic real_close)(int fd);
extern int ntcp_managed_poll(struct pollfd *p, nfds_t n, int timeout);
static int (*_Atomic real_poll)(struct pollfd *p, nfds_t n, int timeout);
extern int ntcp_managed_ppoll(struct pollfd *p, nfds_t n, const struct timespec *t, const sigset_t *mask);
static int (*_Atomic real_ppoll)(struct pollfd *p, nfds_t n, const struct timespec *t, const sigset_t *mask);
extern int ntcp_managed_select(int n, fd_set *r, fd_set *w, fd_set *e, struct timeval *t);
static int (*_Atomic real_select)(int n, fd_set *r, fd_set *w, fd_set *e, struct timeval *t);
extern int ntcp_managed_pselect(int n, fd_set *r, fd_set *w, fd_set *e, const struct timespec *t, const sigset_t *mask);
static int (*_Atomic real_pselect)(int n, fd_set *r, fd_set *w, fd_set *e, const struct timespec *t, const sigset_t *mask);
extern int ntcp_managed_epoll_wait(int fd, struct epoll_event *p, int max, int timeout);
static int (*_Atomic real_epoll_wait)(int fd, struct epoll_event *p, int max, int timeout);
extern int ntcp_managed_epoll_pwait(int fd, struct epoll_event *p, int max, int timeout, const sigset_t *mask);
static int (*_Atomic real_epoll_pwait)(int fd, struct epoll_event *p, int max, int timeout, const sigset_t *mask);
extern int ntcp_managed_epoll_pwait2(int fd, struct epoll_event *p, int max, const struct timespec *t, const sigset_t *mask);
static int (*_Atomic real_epoll_pwait2)(int fd, struct epoll_event *p, int max, const struct timespec *t, const sigset_t *mask);
extern ssize_t ntcp_managed___read_chk(int fd, void *p, size_t n, size_t size);
static ssize_t (*_Atomic real___read_chk)(int fd, void *p, size_t n, size_t size);
extern ssize_t ntcp_managed___recv_chk(int fd, void *p, size_t n, size_t size, int flags);
static ssize_t (*_Atomic real___recv_chk)(int fd, void *p, size_t n, size_t size, int flags);
extern ssize_t ntcp_managed___recvfrom_chk(int fd, void *p, size_t n, size_t size, int flags, struct sockaddr *addr, socklen_t *len);
static ssize_t (*_Atomic real___recvfrom_chk)(int fd, void *p, size_t n, size_t size, int flags, struct sockaddr *addr, socklen_t *len);
extern int ntcp_managed___poll_chk(struct pollfd *p, nfds_t n, int timeout, size_t size);
static int (*_Atomic real___poll_chk)(struct pollfd *p, nfds_t n, int timeout, size_t size);
extern int ntcp_managed___ppoll_chk(struct pollfd *p, nfds_t n, const struct timespec *t, const sigset_t *mask, size_t size);
static int (*_Atomic real___ppoll_chk)(struct pollfd *p, nfds_t n, const struct timespec *t, const sigset_t *mask, size_t size);

static _Atomic int initialized;
static _Thread_local int resolving;
__attribute__((constructor)) static void resolve_boundary(void) {
    resolving = 1;
    real_socket = dlsym(RTLD_NEXT, "socket");
    real_read = dlsym(RTLD_NEXT, "read");
    real_write = dlsym(RTLD_NEXT, "write");
    real_readv = dlsym(RTLD_NEXT, "readv");
    real_writev = dlsym(RTLD_NEXT, "writev");
    real_send = dlsym(RTLD_NEXT, "send");
    real_recv = dlsym(RTLD_NEXT, "recv");
    real_sendto = dlsym(RTLD_NEXT, "sendto");
    real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    real_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
    real_accept = dlsym(RTLD_NEXT, "accept");
    real_accept4 = dlsym(RTLD_NEXT, "accept4");
    real_connect = dlsym(RTLD_NEXT, "connect");
    real_close = dlsym(RTLD_NEXT, "close");
    real_poll = dlsym(RTLD_NEXT, "poll");
    real_ppoll = dlsym(RTLD_NEXT, "ppoll");
    real_select = dlsym(RTLD_NEXT, "select");
    real_pselect = dlsym(RTLD_NEXT, "pselect");
    real_epoll_wait = dlsym(RTLD_NEXT, "epoll_wait");
    real_epoll_pwait = dlsym(RTLD_NEXT, "epoll_pwait");
    real_epoll_pwait2 = dlsym(RTLD_NEXT, "epoll_pwait2");
    real___read_chk = dlsym(RTLD_NEXT, "__read_chk");
    real___recv_chk = dlsym(RTLD_NEXT, "__recv_chk");
    real___recvfrom_chk = dlsym(RTLD_NEXT, "__recvfrom_chk");
    real___poll_chk = dlsym(RTLD_NEXT, "__poll_chk");
    real___ppoll_chk = dlsym(RTLD_NEXT, "__ppoll_chk");
    resolving = 0;
    atomic_store(&initialized, 1);
}

static void ensure_boundary(void) {
    // Also serve earlier preload constructors. Resolver recursion alone uses
    // bootstrap syscalls; after initialization this is only an atomic load.
    if (!atomic_load(&initialized) && !resolving) resolve_boundary();
}

#define MANAGED(type, name, args) do { \
    int state; \
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state); \
    type result = ntcp_managed_##name args; \
    int saved = errno; \
    pthread_setcancelstate(state, NULL); \
    errno = saved; \
    return result; \
} while (0)

ssize_t ntcp_c_read(int fd, void *p, size_t n) {
    ensure_boundary();
    if (internal) { MANAGED(ssize_t, read, (fd,p,n)); }
    if (!real_read) { return syscall(SYS_read,fd,p,n); }
    if (!(ntcp_boundary_fd(fd))) return real_read(fd,p,n);
    MANAGED(ssize_t, read, (fd,p,n));
}

ssize_t ntcp_c_write(int fd, const void *p, size_t n) {
    ensure_boundary();
    if (internal) { MANAGED(ssize_t, write, (fd,p,n)); }
    if (!real_write) { return syscall(SYS_write,fd,p,n); }
    if (!(ntcp_boundary_fd(fd))) return real_write(fd,p,n);
    MANAGED(ssize_t, write, (fd,p,n));
}

ssize_t ntcp_c_readv(int fd, const struct iovec *v, int n) {
    ensure_boundary();
    if (internal) { MANAGED(ssize_t, readv, (fd,v,n)); }
    if (!real_readv) { return syscall(SYS_readv,fd,v,n); }
    if (!(ntcp_boundary_fd(fd))) return real_readv(fd,v,n);
    MANAGED(ssize_t, readv, (fd,v,n));
}

ssize_t ntcp_c_writev(int fd, const struct iovec *v, int n) {
    ensure_boundary();
    if (internal) { MANAGED(ssize_t, writev, (fd,v,n)); }
    if (!real_writev) { return syscall(SYS_writev,fd,v,n); }
    if (!(ntcp_boundary_fd(fd))) return real_writev(fd,v,n);
    MANAGED(ssize_t, writev, (fd,v,n));
}

ssize_t ntcp_c_send(int fd, const void *p, size_t n, int flags) {
    ensure_boundary();
    if (internal) { MANAGED(ssize_t, send, (fd,p,n,flags)); }
    if (!real_send) { return syscall(SYS_sendto,fd,p,n,flags,0,0); }
    if (!(ntcp_boundary_fd(fd))) return real_send(fd,p,n,flags);
    MANAGED(ssize_t, send, (fd,p,n,flags));
}

ssize_t ntcp_c_recv(int fd, void *p, size_t n, int flags) {
    ensure_boundary();
    if (internal) { MANAGED(ssize_t, recv, (fd,p,n,flags)); }
    if (!real_recv) { return syscall(SYS_recvfrom,fd,p,n,flags,0,0); }
    if (!(ntcp_boundary_fd(fd))) return real_recv(fd,p,n,flags);
    MANAGED(ssize_t, recv, (fd,p,n,flags));
}

ssize_t ntcp_c_sendto(int fd, const void *p, size_t n, int flags, const struct sockaddr *addr, socklen_t len) {
    ensure_boundary();
    if (internal) { MANAGED(ssize_t, sendto, (fd,p,n,flags,addr,len)); }
    if (!real_sendto) { return syscall(SYS_sendto,fd,p,n,flags,addr,len); }
    if (!(ntcp_boundary_fd(fd))) return real_sendto(fd,p,n,flags,addr,len);
    MANAGED(ssize_t, sendto, (fd,p,n,flags,addr,len));
}

ssize_t ntcp_c_recvfrom(int fd, void *p, size_t n, int flags, struct sockaddr *addr, socklen_t *len) {
    ensure_boundary();
    if (internal) { MANAGED(ssize_t, recvfrom, (fd,p,n,flags,addr,len)); }
    if (!real_recvfrom) { return syscall(SYS_recvfrom,fd,p,n,flags,addr,len); }
    if (!(ntcp_boundary_fd(fd))) return real_recvfrom(fd,p,n,flags,addr,len);
    MANAGED(ssize_t, recvfrom, (fd,p,n,flags,addr,len));
}

ssize_t ntcp_c_sendmsg(int fd, const struct msghdr *p, int flags) {
    ensure_boundary();
    if (internal) { MANAGED(ssize_t, sendmsg, (fd,p,flags)); }
    if (!real_sendmsg) { return syscall(SYS_sendmsg,fd,p,flags); }
    if (!(ntcp_boundary_fd(fd))) return real_sendmsg(fd,p,flags);
    MANAGED(ssize_t, sendmsg, (fd,p,flags));
}

ssize_t ntcp_c_recvmsg(int fd, struct msghdr *p, int flags) {
    ensure_boundary();
    if (internal) { MANAGED(ssize_t, recvmsg, (fd,p,flags)); }
    if (!real_recvmsg) { return syscall(SYS_recvmsg,fd,p,flags); }
    if (!(ntcp_boundary_fd(fd))) return real_recvmsg(fd,p,flags);
    MANAGED(ssize_t, recvmsg, (fd,p,flags));
}

int ntcp_c_accept(int fd, struct sockaddr *p, socklen_t *len) {
    ensure_boundary();
    if (internal) { MANAGED(int, accept, (fd,p,len)); }
    if (!real_accept) { return syscall(SYS_accept,fd,p,len); }
    if (!(ntcp_boundary_fd(fd))) return real_accept(fd,p,len);
    MANAGED(int, accept, (fd,p,len));
}

int ntcp_c_accept4(int fd, struct sockaddr *p, socklen_t *len, int flags) {
    ensure_boundary();
    if (internal) { MANAGED(int, accept4, (fd,p,len,flags)); }
    if (!real_accept4) { return syscall(SYS_accept4,fd,p,len,flags); }
    if (!(ntcp_boundary_fd(fd))) return real_accept4(fd,p,len,flags);
    MANAGED(int, accept4, (fd,p,len,flags));
}

int ntcp_c_connect(int fd, const struct sockaddr *p, socklen_t len) {
    ensure_boundary();
    if (internal) { MANAGED(int, connect, (fd,p,len)); }
    if (!real_connect) { return syscall(SYS_connect,fd,p,len); }
    if (!(ntcp_boundary_fd(fd))) return real_connect(fd,p,len);
    MANAGED(int, connect, (fd,p,len));
}

int ntcp_c_close(int fd) {
    ensure_boundary();
    if (internal) { MANAGED(int, close, (fd)); }
    if (!real_close) { return syscall(SYS_close,fd); }
    if (!(ntcp_boundary_fd(fd) || ntcp_boundary_epoll(fd))) return real_close(fd);
    MANAGED(int, close, (fd));
}

int ntcp_c_poll(struct pollfd *p, nfds_t n, int timeout) {
    ensure_boundary();
    if (internal) { MANAGED(int, poll, (p,n,timeout)); }
    if (!real_poll) { return syscall(SYS_poll,p,n,timeout); }
    if (!(ntcp_boundary_poll(p,n))) return real_poll(p,n,timeout);
    MANAGED(int, poll, (p,n,timeout));
}

int ntcp_c_ppoll(struct pollfd *p, nfds_t n, const struct timespec *t, const sigset_t *mask) {
    ensure_boundary();
    if (internal) { MANAGED(int, ppoll, (p,n,t,mask)); }
    if (!real_ppoll) { errno = ENOSYS; return -1; }
    if (!(ntcp_boundary_poll(p,n))) return real_ppoll(p,n,t,mask);
    MANAGED(int, ppoll, (p,n,t,mask));
}

int ntcp_c_select(int n, fd_set *r, fd_set *w, fd_set *e, struct timeval *t) {
    ensure_boundary();
    if (internal) { MANAGED(int, select, (n,r,w,e,t)); }
    if (!real_select) { return syscall(SYS_select,n,r,w,e,t); }
    if (!(ntcp_boundary_select(n,r,w,e))) return real_select(n,r,w,e,t);
    MANAGED(int, select, (n,r,w,e,t));
}

int ntcp_c_pselect(int n, fd_set *r, fd_set *w, fd_set *e, const struct timespec *t, const sigset_t *mask) {
    ensure_boundary();
    if (internal) { MANAGED(int, pselect, (n,r,w,e,t,mask)); }
    if (!real_pselect) { errno = ENOSYS; return -1; }
    if (!(ntcp_boundary_select(n,r,w,e))) return real_pselect(n,r,w,e,t,mask);
    MANAGED(int, pselect, (n,r,w,e,t,mask));
}

int ntcp_c_epoll_wait(int fd, struct epoll_event *p, int max, int timeout) {
    ensure_boundary();
    if (internal) { MANAGED(int, epoll_wait, (fd,p,max,timeout)); }
    if (!real_epoll_wait) { return syscall(SYS_epoll_wait,fd,p,max,timeout); }
    if (!(ntcp_boundary_epoll(fd))) return real_epoll_wait(fd,p,max,timeout);
    MANAGED(int, epoll_wait, (fd,p,max,timeout));
}

int ntcp_c_epoll_pwait(int fd, struct epoll_event *p, int max, int timeout, const sigset_t *mask) {
    ensure_boundary();
    if (internal) { MANAGED(int, epoll_pwait, (fd,p,max,timeout,mask)); }
    if (!real_epoll_pwait) { errno = ENOSYS; return -1; }
    if (!(ntcp_boundary_epoll(fd))) return real_epoll_pwait(fd,p,max,timeout,mask);
    MANAGED(int, epoll_pwait, (fd,p,max,timeout,mask));
}

int ntcp_c_epoll_pwait2(int fd, struct epoll_event *p, int max, const struct timespec *t, const sigset_t *mask) {
    ensure_boundary();
    if (internal) { MANAGED(int, epoll_pwait2, (fd,p,max,t,mask)); }
    if (!real_epoll_pwait2) { errno = ENOSYS; return -1; }
    if (!(ntcp_boundary_epoll(fd))) return real_epoll_pwait2(fd,p,max,t,mask);
    MANAGED(int, epoll_pwait2, (fd,p,max,t,mask));
}

ssize_t ntcp_c___read_chk(int fd, void *p, size_t n, size_t size) {
    ensure_boundary();
    if (internal) { MANAGED(ssize_t, __read_chk, (fd,p,n,size)); }
    if (!real___read_chk) { errno = ENOSYS; return -1; }
    if (!(ntcp_boundary_fd(fd))) return real___read_chk(fd,p,n,size);
    MANAGED(ssize_t, __read_chk, (fd,p,n,size));
}

ssize_t ntcp_c___recv_chk(int fd, void *p, size_t n, size_t size, int flags) {
    ensure_boundary();
    if (internal) { MANAGED(ssize_t, __recv_chk, (fd,p,n,size,flags)); }
    if (!real___recv_chk) { errno = ENOSYS; return -1; }
    if (!(ntcp_boundary_fd(fd))) return real___recv_chk(fd,p,n,size,flags);
    MANAGED(ssize_t, __recv_chk, (fd,p,n,size,flags));
}

ssize_t ntcp_c___recvfrom_chk(int fd, void *p, size_t n, size_t size, int flags, struct sockaddr *addr, socklen_t *len) {
    ensure_boundary();
    if (internal) { MANAGED(ssize_t, __recvfrom_chk, (fd,p,n,size,flags,addr,len)); }
    if (!real___recvfrom_chk) { errno = ENOSYS; return -1; }
    if (!(ntcp_boundary_fd(fd))) return real___recvfrom_chk(fd,p,n,size,flags,addr,len);
    MANAGED(ssize_t, __recvfrom_chk, (fd,p,n,size,flags,addr,len));
}

int ntcp_c___poll_chk(struct pollfd *p, nfds_t n, int timeout, size_t size) {
    ensure_boundary();
    if (internal) { MANAGED(int, __poll_chk, (p,n,timeout,size)); }
    if (!real___poll_chk) { errno = ENOSYS; return -1; }
    if (!(ntcp_boundary_poll(p,n))) return real___poll_chk(p,n,timeout,size);
    MANAGED(int, __poll_chk, (p,n,timeout,size));
}

int ntcp_c___ppoll_chk(struct pollfd *p, nfds_t n, const struct timespec *t, const sigset_t *mask, size_t size) {
    ensure_boundary();
    if (internal) { MANAGED(int, __ppoll_chk, (p,n,t,mask,size)); }
    if (!real___ppoll_chk) { errno = ENOSYS; return -1; }
    if (!(ntcp_boundary_poll(p,n))) return real___ppoll_chk(p,n,t,mask,size);
    MANAGED(int, __ppoll_chk, (p,n,t,mask,size));
}

int ntcp_c_socket(int domain, int kind, int protocol) {
    ensure_boundary();
    if (!real_socket || internal) return syscall(SYS_socket, domain, kind, protocol);
    if (!ntcp_boundary_socket(domain, kind)) return real_socket(domain, kind, protocol);
    MANAGED(int, socket, (domain, kind, protocol));
}
